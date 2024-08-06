import streamlit as st
import os
import re
import logging
import urllib.parse
from uuid import UUID
from sqlalchemy import create_engine
from langchain.agents import create_sql_agent
from langchain.agents.agent_toolkits import SQLDatabaseToolkit
from langchain.sql_database import SQLDatabase
from langchain_community.chat_models import ChatOpenAI
from langchain.agents.agent_types import AgentType
from langchain.schema import HumanMessage

st.set_page_config(page_title="BugBuster", page_icon="🐞", layout="wide")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

st.write(
    os.environ["OPENAI_API_KEY"] == st.secrets["OPENAI_API_KEY"],
    os.environ["DB_USERNAME"] == st.secrets["DB_USERNAME"],
    os.environ["DB_PASSWORD"] == st.secrets["DB_PASSWORD"],
    os.environ["DB_HOST"] == st.secrets["DB_HOST"],
    os.environ["DB_NAME"] == st.secrets["DB_NAME"],
    os.environ["DB_PORT"] == st.secrets["DB_PORT"],
)


def create_postgres_engine():
    try:
        username = os.getenv("DB_USERNAME")
        password = os.getenv("DB_PASSWORD")
        host = os.getenv("DB_HOST")
        database_name = os.getenv("DB_NAME")
        port = os.getenv("DB_PORT")

        if not all([username, password, host, database_name, port]):
            raise ValueError("Missing required database environment variables")

        encoded_password = urllib.parse.quote_plus(password)
        postgres_uri = f"postgresql://{username}:{encoded_password}@{host}:{port}/{database_name}"
        st.write(f"Attempting to connect to: {host}:{port}/{database_name} as {username}")
        engine = create_engine(postgres_uri)
        return engine, postgres_uri
    except Exception as e:
        st.error(f"Failed to create Postgres engine: {str(e)}")
        raise

def setup_sqlchain_agent(postgres_uri):
    """Set up and return an SQL agent using the provided PostgreSQL URI."""
    try:
        openai_api_key = os.getenv("OPENAI_API_KEY")
        if not openai_api_key:
            raise ValueError("Missing OpenAI API key in environment variables")

        db = SQLDatabase.from_uri(postgres_uri)
        llm = ChatOpenAI(temperature=0, openai_api_key=openai_api_key, model_name='gpt-3.5-turbo')
        toolkit = SQLDatabaseToolkit(db=db, llm=llm)
        
        agent_executor = create_sql_agent(
            llm=llm,
            toolkit=toolkit,
            verbose=True,
            agent_type=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        )
        
        return agent_executor
    except Exception as e:
        logger.error(f"Failed to set up SQLChain agent: {str(e)}")
        raise

def query_database_with_agent(agent_executor, query):
    """Execute a query using the provided SQL agent."""
    try:
        result = agent_executor.run(query)
        return result
    except Exception as e:
        logger.error(f"Failed to query database: {str(e)}")
        raise

def parse_sql_result(sql_result_str):
    """Parse the SQL result string into a structured format."""
    try:
        # Remove any leading/trailing whitespace and brackets
        cleaned_str = sql_result_str.strip()[1:-1]
        
        # Split the string into individual items
        items = re.findall(r'(?:[^,()]|\([^)]*\))+', cleaned_str)
        
        processed_items = []
        for item in items:
            item = item.strip()
            if item.startswith('UUID('):
                uuid_str = re.search(r"'([^']*)'", item).group(1)
                processed_items.append(UUID(uuid_str))
            elif item.startswith('datetime.datetime('):
                processed_items.append(item)  # Keep as string representation
            elif item == 'None':
                processed_items.append(None)
            elif item.startswith("'") and item.endswith("'"):
                processed_items.append(item[1:-1])
            else:
                try:
                    processed_items.append(eval(item))
                except:
                    processed_items.append(item)
        
        return tuple(processed_items)
    except Exception as e:
        logger.error(f"Error parsing SQL result: {str(e)}")
        logger.error(f"SQL result string: {sql_result_str}")
        raise

def parse_submission_data(sql_result):
    """Extract relevant submission data from the SQL result."""
    try:
        return {
            'submissions_id': sql_result[1],
            'submission_title': sql_result[2],
            'detail_description': sql_result[3],
            'step_to_reproduce': sql_result[4],
            'remediation_recommendation': sql_result[5],
            'severity': sql_result[6],
            'priority': sql_result[7],
            'target_url1': sql_result[10],
            'target_url2': sql_result[11],
            'target_url3': sql_result[12],
            'type_of_testing_allowed': sql_result[16],
            'languages_frameworks': sql_result[17],
            'asset_environments': sql_result[18],
            'submission_status': sql_result[32]
        }
    except Exception as e:
        logger.error(f"Error parsing submission data: {str(e)}")
        raise

def parse_user_input(user_input):
    """Parse natural language user input to extract submission ID and tool/framework/language."""
    
    # Define pattern for submission ID
    submission_id_pattern = r'(?:BSB|bsb)\d{12}'

    # Find submission ID
    submission_id_match = re.search(submission_id_pattern, user_input, re.IGNORECASE)
    submission_id = submission_id_match.group(0) if submission_id_match else None

    if not submission_id:
        return None, None, None

    # Define keywords for tools and languages
    tools = ['burp suite', 'burpsuite', 'metasploit', 'msfconsole', 'msfvenom', 'nmap', 'sqlmap', 'wireshark', 'nikto']
    languages = ['python', 'javascript', 'js', 'java', 'c++', 'ruby', 'go', 'php', 'bash', 'powershell']
    all_keywords = tools + languages

    # Convert input to lowercase for case-insensitive matching
    user_input_lower = user_input.lower()

    # Find tool or language
    tool_or_language = next((keyword for keyword in all_keywords if keyword in user_input_lower), None)

    # If no specific tool or language is found, return 'general'
    if not tool_or_language:
        return submission_id, 'general', None

    # If a programming language is specified, set tool to 'code'
    if tool_or_language in languages:
        return submission_id, 'code', tool_or_language
    else:
        return submission_id, tool_or_language, None

def generate_test_content(submission_data, tool='general', language=None):
    """Generate test content based on the submission data, specified tool, and language."""
    try:
        openai_api_key = os.getenv("OPENAI_API_KEY")
        if not openai_api_key:
            raise ValueError("Missing OpenAI API key in environment variables")

        llm = ChatOpenAI(temperature=0, openai_api_key=openai_api_key, model_name='gpt-3.5-turbo')
        
        if tool == 'code':
            prompt = f"""
            Generate {language} code to test the vulnerability based on the following submission:

            - Submission ID: {submission_data['submissions_id']}
            - Title: {submission_data['submission_title']}
            - Description: {submission_data['detail_description']}
            - Steps to Reproduce: {submission_data['step_to_reproduce']}
            - Remediation Recommendation: {submission_data['remediation_recommendation']}
            - Severity: {submission_data['severity']}
            - Priority: {submission_data['priority']}
            - Target URLs: {submission_data['target_url1']}, {submission_data['target_url2']}, {submission_data['target_url3']}
            - Type of Testing Allowed: {submission_data['type_of_testing_allowed']}
            - Languages/Frameworks: {submission_data['languages_frameworks']}
            - Asset Environments: {submission_data['asset_environments']}

            Please provide {language} code that:
            1. Demonstrates the vulnerability
            2. Follows ethical hacking practices
            3. Only targets the specified URLs
            4. Includes proper error handling and logging
            5. Provides comments explaining the code and its relation to the vulnerability
            6. Suggests how the code could be used to verify the proposed remediation

            Important: Ensure the code is ethical and includes appropriate safeguards. Provide a disclaimer about responsible use.
            """
        else:
            prompt = f"""
            Generate commands or a script to test the vulnerability using {tool} based on the following submission:

            - Submission ID: {submission_data['submissions_id']}
            - Title: {submission_data['submission_title']}
            - Description: {submission_data['detail_description']}
            - Steps to Reproduce: {submission_data['step_to_reproduce']}
            - Remediation Recommendation: {submission_data['remediation_recommendation']}
            - Severity: {submission_data['severity']}
            - Priority: {submission_data['priority']}
            - Target URLs: {submission_data['target_url1']}, {submission_data['target_url2']}, {submission_data['target_url3']}
            - Type of Testing Allowed: {submission_data['type_of_testing_allowed']}
            - Languages/Frameworks: {submission_data['languages_frameworks']}
            - Asset Environments: {submission_data['asset_environments']}

            Please provide commands or a script for {tool} that:
            1. Demonstrates the vulnerability
            2. Follows ethical hacking practices
            3. Only targets the specified URLs
            4. Includes proper error handling and logging
            5. Provides comments explaining the commands/script and their relation to the vulnerability
            6. Suggests how the commands/script could be used to verify the proposed remediation

            If the tool is not specified (general), provide a high-level approach using appropriate cybersecurity tools.

            Important: Ensure the commands/script are ethical and include appropriate safeguards. Provide a disclaimer about responsible use.
            """

        messages = [HumanMessage(content=prompt)]
        response = llm.invoke(messages)
        return response.content
    except Exception as e:
        logger.error(f"Error generating test content: {str(e)}")
        raise

def main():
    
    st.title("🐞 BugBuster")
    st.subheader("Vulnerability Testing Assistant")

    # Sidebar for app information
    with st.sidebar:
        st.header("About BugBuster")
        st.info(
            "BugBuster is an AI-powered tool that helps security researchers "
            "generate test scripts and commands for vulnerability testing. "
            "Simply enter a submission ID and specify a tool or language, "
            "and BugBuster will provide you with tailored testing content."
        )
        st.warning(
            "⚠️ Disclaimer: Always use this tool responsibly and ethically. "
            "Ensure you have proper authorization before testing any systems."
        )

    # Main app layout
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        user_input = st.text_input(
            "Enter your request",
            placeholder="e.g., 'Test BSB000000000057 in Python' or 'Use Burp Suite for BSB000000000057'"
        )
        
        if st.button("Generate Test Content", type="primary"):
            if user_input:
                try:
                    # Create engine and get postgres URI
                    _, postgres_uri = create_postgres_engine()
                    
                    # Setup SQLChain agent
                    agent_executor = setup_sqlchain_agent(postgres_uri)
                    
                    # Parse user input
                    submission_id, tool, language = parse_user_input(user_input)
                    
                    if not submission_id:
                        st.error("Could not determine the submission ID from your input. Please include a valid BSB number.")
                    else:
                        with st.spinner("Generating test content..."):
                            # Query to get submission details
                            query = f"SELECT * FROM submission_submission WHERE submissions_id = '{submission_id}'"
                            
                            # Run query using the agent
                            result = query_database_with_agent(agent_executor, query)
                            
                            # Extract SQL result from the agent's response
                            sql_result_match = re.search(r'\[(.*?)\]', result, re.DOTALL)
                            if sql_result_match:
                                sql_result_str = sql_result_match.group(0)
                                sql_result = parse_sql_result(sql_result_str)
                                submission_data = parse_submission_data(sql_result)
                                
                                # Generate testing content
                                test_content = generate_test_content(submission_data, tool, language)
                                
                                st.success("Test content generated successfully!")
                                
                                # Display submission details
                                with st.expander("Submission Details", expanded=True):
                                    st.json(submission_data)
                                
                                # Display generated content
                                st.subheader("Generated Test Content")
                                st.code(test_content, language=language if tool == 'code' else None)
                                
                                # Add a download button for the generated content
                                st.download_button(
                                    label="Download Test Content",
                                    data=test_content,
                                    file_name=f"bugbuster_{submission_id}_{tool}_{language}.txt",
                                    mime="text/plain"
                                )
                            else:
                                st.warning(f"No data found for submission ID: {submission_id}")
                except Exception as e:
                    st.error(f"An error occurred: {str(e)}")
            else:
                st.warning("Please enter a request to generate test content.")

if __name__ == "__main__":
    main()

