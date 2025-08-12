
import json
import re
import streamlit as st
import os
import base64
import streamlit.components.v1 as components
from PIL import Image
from io import BytesIO
from io import StringIO
from openai import OpenAI
from openai import AzureOpenAI

global app_input

# ------------------ Helper Functions ------------------ #


    
# Function to create a prompt for generating a components table
def create_components_prompt(app_input):
    prompt = f"""
generate a list of components.

When providing the components, use a JSON formatted response with the key "components_table". Under "components_table", include an array of objects with the keys "Component", "Description", and "Technology Context" where "Description" describes what the component is and how it relates to the system and "Technology Context" documents specific technologies of a given componenent. For example, a component may be a web application and the technology context could be the language its programmed in such as javascript.

It is very important that your responses are tailored to reflect the details you are given.

Do not assume anything. If the description does not specify it. It should not be included.

APPLICATION DESCRIPTION: {app_input}

Example of expected JSON response format:
  
    {{
      "components_table": [
        {{
          "Component": "Web Application",
          "Description": "Example Description 1",
          "Technology Context": "Example Tech Context 1"
        }},
        {{
          "Component": "Database Server",
          "Description": "Example Description 2",
          "Technology Context": "Example Tech Contexts 2"
        }},
        // ... more components
      ]
    }}
"""
    return prompt
    
# Function to create a prompt for generating a ags table
def create_attack_goals_prompt(app_input):
    prompt = f"""
generate a list of attack goals.

When providing the attack goals, use a JSON formatted response with the key "ag_table". Under "ag_table", include an array of objects with the keys "Attack Goals" and "Description" where each attack goal describes what and attack can do and what they may be able to achieve such as gain access to a privileged account.

Attack goal examples: 1. Become domain admin (domain admin account) 2. Getting root (root account) 3. Bypassing the second factor (there is no asset here - we are just trying to weaken security) 4. Stealing compute time crypto mining (compute resource)
It is very important that your responses are tailored to reflect the details you are given.

Do not assume anything. If the description does not specify it. It should not be included.

APPLICATION DESCRIPTION: {app_input}

Example of expected JSON response format:
  
    {{
      "ag_table": [
        {{
          "Attack Goal": "Account Takeover",
          "Description": "Example Description 1"
        }},
        {{
          "Attack Goal": "Exfiltrate Data",
          "Description": "Example Description 2"
        }},
        // ... more ags
      ]
    }}
"""
    return prompt

# Function to create a prompt for generating a controls table
def create_controls_prompt(app_input):
    prompt = f"""
generate a list of controls.

When providing the controls, use a JSON formatted response with the key "controls_table". Under "controls_table", include an array of objects with the keys "Controls", "Description" and "Compliance" where each control describes a control that should exist based on the context you were provided. Avoid being too generic. The "Compliance" column state if a control exists or not, based solely on the information provided.

It is very important that your responses are tailored to reflect the details you are given.

Do not assume anything. If the description does not specify it. It should not be included.

APPLICATION DESCRIPTION: {app_input}

Example of expected JSON response format:
  
    {{
      "controls_table": [
        {{
          "Control": "Encryption at Rest",
          "Description": "Example Description 1",
          "Compliance": "This control appears to exist"
        }},
        {{
          "Control": "Authentication",
          "Description": "Example Description 2",
          "Compliance": "This control may not exist"
        }},
        // ... more controls
      ]
    }}
"""
    return prompt
    
# Function to create a prompt for generating a assets table
def create_assets_prompt(app_input):
    prompt = f"""
generate a list of assets.

When providing the assets, use a JSON formatted response with the key "assets_table". Under "assets_table", include an array of objects with the keys "Assets" and "Description" where each asset is what an attacker may be after, such as accounts, privileges, services, etc.

It is very important that your responses are tailored to reflect the details you are given.

Do not assume anything. If the description does not specify it. It should not be included.

APPLICATION DESCRIPTION: {app_input}

Example of expected JSON response format:
  
    {{
      "assets_table": [
        {{
          "Asset": "User Accounts",
          "Description": "Example Description 1"
        }},
        {{
          "Asset": "User Data",
          "Description": "Example Description 2"
        }},
        // ... more controls
      ]
    }}
"""
    return prompt
    
    
# Function to create a prompt for generating a trace matrix table
def create_trace_matrix_prompt(app_input):
    prompt = f"""
generate a list of threats in a tracebility form. A traceability matrix is a connect form to represent an attack that may read as "The 'threat agent' has an 'attack goal' in which they execute an 'attack' via an 'attack surface' to gain access to an 'asset' which may or may not be protected by a 'control'"

When providing the traace matrix, use a JSON formatted response with the key "trace_matrix_table". Under "trace_matrix_table", include an array of objects with the keys "Threat Agent", "Attack Goal", "Attack Surface", "Attack", "Assetss, "Controls" and "Potential Impact" where each entry in the matrix represents a single threat scenario. "Potential Impact" should be represented by "High", "Medium" or "Low" with a brief description of why and "Attack" is represented by a CAPEC ID or STRIDE category where applicable. A small description of the attack is required.

It is very important that your responses are tailored to reflect the details you are given.

Do not assume anything. If the description does not specify it. It should not be included.

APPLICATION DESCRIPTION: {app_input}

Example of expected JSON response format:
  
    {{
      "trace_matrix_table": [
        {{
          "Threat Agent": "Malicious User",
          "Attack Goal": "Example Attack Goal 1",
          "Attack Surface": "Example Attack Surface 1",
          "Attack": "Example Attack 1",
          "Asset": "Example Asset 1",
          "Control": "Example Control 1",
          "Potential Impact": "Potential Impact 1"
        }},
        {{
          "Threat Agent": "Nation State",
          "Attack Goal": "Example Attack Goal 2",
          "Attack Surface": "Example Attack Surface 2",
          "Attack": "Example Attack 2",
          "Asset": "Example Asset 2",
          "Control": "Example Control 2",
          "Potential Impact": "Potential Impact 2"
        }},
        // ... more trace matrix
      ]
    }}
"""
    return prompt

# Function to create a prompt for generating a attack surfaces table
def create_surfaces_prompt(app_input):
    prompt = f"""
generate a list of attack surfaces.

When providing the attack surfaces, use a JSON formatted response with the key "surfaces_table". Under "surfaces_table", include an array of objects with the keys "Attack Surfaces" and "Description" where each attack surface describes the component or interface an attacker may use to compromise a system. 

It is very important that your responses are tailored to reflect the details you are given.

Do not assume anything. If the description does not specify it. It should not be included.


APPLICATION DESCRIPTION: {app_input}

Example of expected JSON response format:
  
    {{
      "surfaces_table": [
        {{
          "Attack Surface": "Unencrypted Communication (HTTP)",
          "Description": "Example Description 1"
        }},
        {{
          "Attack Surface": "File Upload Functionality",
          "Description": "Example Description 2"
        }},
        // ... more attack surfaces
      ]
    }}
"""
    return prompt
    
# Function to create a prompt for generating a attack surfaces table
def create_attackers_prompt(app_input):
    prompt = f"""
generate a list of attackers.

When providing the attackers, use a JSON formatted response with the key "attackers_table". Under "attackers_table", include an array of objects with the keys "Attackers" and "Description" where each attacker is described based on level of access and location. 

It is very important that your responses are tailored to reflect the details you are given.

Do not assume anything. If the description does not specify it. It should not be included.

APPLICATION DESCRIPTION: {app_input}

Example of expected JSON response format:
  
    {{
      "attackers_table": [
        {{
          "Attackers": "Malicious User",
          "Description": "Example Description 1"
        }},
        {{
          "Attack Surface": "Disgruntled Employee",
          "Description": "Example Description 2"
        }},
        // ... more attackers
      ]
    }}
"""
    return prompt
    
def generate_drawio_prompt(app_input,stencil):
    prompt = f"""You are an expert threat modeler. You are tasked with write the xml to produce a drawio diagram using a specific xml template. You must use the provided template to create your objects - do not introduce any new or additional objects or styles.
The stencil contains some specific objects that should be used in certain ways. 1. a "component" a component is an object to describe all the elements of a system. For example, a web application is a component, a service is also a component. 
The "database" is a specific type of component used for data storage. A "trust boundary" typically used to separate different layers, i.e. internet from internal networks. A "container" is used to contain several or many components, such as microservices. Each service would be a component in the container shape. The "connection" object is used to highlight how data is trasmitted between two components, such as HTTP.
You should change the title as appropriate to describe what the component is - however it should be simple, such as DynamoDB or Mobile Application. You must not add comments or additional text. It must be a well-formatted XML file using components from the provided stencil. All "<" and ">" characters within a proper tag should be execaped. The stencil is here: {stencil}

The application description here: {app_input}"""

    return prompt
    
#send image for pocessing
def process_image(openai_api_key,image):
    buffered = BytesIO()
    image.save(buffered, format="JPEG")
    img_byte_data = buffered.getvalue()
    base64_image = base64.b64encode(img_byte_data).decode('utf-8')
    
    client = OpenAI(api_key=openai_api_key, base_url="https://llm.labs.polaris.synopsys.com/v1")
    
    response = client.chat.completions.create(
        model="gpt-4o",
        max_tokens=4000,
        temperature=0,
        messages = [
            {
            "role": "system",
            "content": "You are an expert architect. You will be presented with a system diagram that you need to describe in text."
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"}
                    },
                    {
                        "type": "text",
                        "text": "As a system architect looking to perform a threat model please review the diagram provided and describe what you see to a new technical member to the team. The description should only include details as provided in the diagram only. Do not assume anything. Do not attempt to perform a threat model. This is a descriptive exercise only. Based on the diagram only, describe how data may flow between various components. If you can extract protocol and connection information, include that in description as well."
                    }
                ]
            }
        ],
    )
    
    response_content = response.choices[0].message.content

    return response_content
    
    
# Function to get parsed data
def get_threat_model(openai_api_key, prompt):
    client = OpenAI(api_key=openai_api_key, base_url="https://llm.labs.polaris.synopsys.com/v1")

    response = client.chat.completions.create(
        model="gpt-4o",
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=4000,
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    response_content = json.loads(response.choices[0].message.content)

    return response_content
    
def get_drawio(openai_api_key, prompt):
    client = OpenAI(api_key=openai_api_key, base_url="https://llm.labs.polaris.synopsys.com/v1")

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output a drawio XML. "},
            {"role": "user", "content": prompt}
        ],
        max_tokens=4000,
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    #response_content = json.loads(response.choices[0].message.content)

    return response.choices[0].message.content

 
# Function to convert JSON to Markdown for display for components   
def json_to_markdown_component(components_table):
    markdown_output = "## Components\n\n"
    
    # Start the markdown table with headers
    markdown_output += "| Component | Description | Technology Context |\n"
    markdown_output += "|-------------|----------|------------------|\n"
    
    # Fill the table rows with the component data
    for threat in components_table:
        markdown_output += f"| {threat['Component']} | {threat['Description']} | {threat['Technology Context']} |\n"
       
    return markdown_output
    
# Function to convert JSON to Markdown for display for ags 
def json_to_markdown_ag(ag_table):
    markdown_output = "## Attack Goals\n\n"
    
    # Start the markdown table with headers
    markdown_output += "| Attack Goal | Description |\n"
    markdown_output += "|-------------|----------|\n"
    
    # Fill the table rows with the component data
    for threat in ag_table:
        markdown_output += f"| {threat['Attack Goal']} | {threat['Description']}|\n"
       
    return markdown_output
    
# Function to convert JSON to Markdown for display for controls 
def json_to_markdown_controls(controls_table):
    markdown_output = "## Controls\n\n"
    
    # Start the markdown table with headers
    markdown_output += "| Controls | Description | Compliance |\n"
    markdown_output += "|-------------|----------|----------|\n"
    
    # Fill the table rows with the controls data
    for threat in controls_table:
        markdown_output += f"| {threat['Control']} | {threat['Description']}|{threat['Compliance']}|\n"
       
    return markdown_output
    
# Function to convert JSON to Markdown for display for attack surfaces 
def json_to_markdown_surfaces(surfaces_table):
    markdown_output = "## Attack Surfaces\n\n"
    
    # Start the markdown table with headers
    markdown_output += "| Attack Surfaces | Description |\n"
    markdown_output += "|-------------|----------|\n"
    
    # Fill the table rows with the attack surfaces data
    for threat in surfaces_table:
        markdown_output += f"| {threat['Attack Surface']} | {threat['Description']}|\n"
       
    return markdown_output
    
# Function to convert JSON to Markdown for display for attackers 
def json_to_markdown_attackers(attackers_table):
    markdown_output = "## Attackers\n\n"
    
    # Start the markdown table with headers
    markdown_output += "| Attackers | Description |\n"
    markdown_output += "|-------------|----------|\n"
    
    # Fill the table rows with the attackers data
    for threat in attackers_table:
        markdown_output += f"| {threat['Attackers']} | {threat['Description']}|\n"
       
    return markdown_output
 
def json_to_markdown_matrix(trace_matrix_table):
    markdown_output = "## Traceability Matrix\n\n"
    
    # Start the markdown table with headers
    markdown_output += "| Threat Agent | Attack Goal | Attack Surface | Attack | Asset | Controls | Potential Impact |\n"
    markdown_output += "|-------------|----------|-------------|----------|-------------|----------|-------------|\n"
    
    # Fill the table rows with the trace matrix data
    for threat in trace_matrix_table:
        markdown_output += f"| {threat['Threat Agent']} | {threat['Attack Goal']}|{threat['Attack Surface']} | {threat['Attack']}|{threat['Asset']} | {threat['Control']}|{threat['Potential Impact']} |\n"
       
    return markdown_output

# ------------------ Streamlit UI Configuration ------------------ #

st.set_page_config(
    page_title="TM Automation",
    page_icon=":shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Create three columns
col1, col2, col3, col4 = st.columns(4)


# ------------------ Main App UI ------------------ #

# Get api key
openai_api_key = st.text_input(
            "Enter your OpenAI API key:",
            type="password",
        )
tab1, tab2 = st.tabs(["Diagramming", "Analysis"])

with tab1:
    description_to_draw = st.text_input(
            "Write a description of the system to be drawn",
            type="default"
        )
    stencil = st.file_uploader("Please upload your drawio stencil")
    if stencil is not None:     
        string_data = StringIO(stencil.getvalue().decode("utf-8")).read()
        if description_to_draw:
            drawio_button = st.button(label="Generate DrawIO XML")
            if drawio_button:
                drawio_prompt = generate_drawio_prompt(description_to_draw, string_data)
                drawio_xml = get_drawio(openai_api_key, drawio_prompt)
                st.write(drawio_xml)
        
        
with tab2:
    with col1:
        st.image("ai_robot.png", use_column_width =True)

    with col2:
        st.title("Threat Modeling Automation Assistant", anchor=None, help=None)

    
            
    uploaded_image = st.file_uploader("Please upload an image of the system you would like analyzed. Currently, JPEG is the only working format", type=["jpg", "jpeg", "png"])
        
    if uploaded_image is not None:
        image = Image.open(uploaded_image)
        st.image(image, caption="Uploaded Image", width=450)
        app_input = process_image(openai_api_key, image)
        # processing_result = process_image_with_chatgpt(image)
        st.text_area("The following is the description of the system provided. This description will be used for the threat modeling activities:", value=app_input, height=200)

    # ------------------ Sidebar ------------------ #

    # Add instructions on how to use the app to the sidebar
    st.sidebar.header("Welcome to the Threat Modeling Automation Assistance")

    with st.sidebar:
        st.markdown("""An application designed to streamline the threat modeling process for architecture diagrams.""")
        st.markdown("""This application leverages advanced image processing and natural language processing capabilities to generate comprehensive threat models.""")
        st.markdown("""The workflow begins with the user uploading an architectural diagram image file. The application then encodes the image into a base64 representation and submits it to the OpenAI service for analysis. OpenAI's sophisticated models interpret the image and provide a detailed description of the depicted architecture.""")
        st.markdown("""The application then consumes the output and utilizes OpenAI's language models to generate a comprehensive list of assets, controls, attack surfaces, and other relevant components based on the architecture description. This information is then organized into a traceability matrix, providing a clear and structured view of the potential threats and corresponding mitigation measures.""")
        st.markdown("""By automating the threat modeling process, this application streamlines a traditionally time-consuming and error-prone task, enabling organizations to proactively identify and address security risks in their architectural designs efficiently and accurately.""")
        


    # ------------------ Components Table Generation ------------------ #
    with st.expander("Components", expanded=False):
        # Create a submit button for Components Table
        components_table_submit_button = st.button(label="Generate Components Table")

        # If the Generate Components Table button is clicked and the user has provided an application description
        if components_table_submit_button and app_input:
            # Generate the prompt using the create_prompt function
            components_prompt = create_components_prompt(app_input)

            # Show a spinner while generating the components table
            with st.spinner("Generating components..."):
                try:
                    # Call one of the get_components functions with the generated prompt
                    
                    #if model_provider == "OpenAI API":
                    model_output = get_threat_model(openai_api_key, components_prompt)
                                    
                    # Access the components from parsed content
                    
                    components_table = model_output.get("components_table", [])
                    
                    # Save the component table to the session state for later use in mitigations
                    st.session_state['components_table'] = components_table

                    # Convert the component table JSON to Markdown
                    markdown_output = json_to_markdown_component(components_table)
                    

                    # Display the component table in Markdown
                    st.markdown(markdown_output)

                except Exception as e:
                    st.error(f"Error generating components table: {e}")

                # Add a button to allow the user to download the output as a Markdown file
                st.download_button(
                    label="Download Components Table",
                    data=markdown_output,  # Use the Markdown output
                    file_name="components_tables.md",
                    mime="text/markdown",
                )

        # If the submit button is clicked and the user has not provided an application description
        if components_table_submit_button and not app_input:
            st.error("Please enter your application details before submitting.")
            
    # ------------------ Attack Goals Table Generation ------------------ #
    with st.expander("Attack Goals", expanded=False):
        # Create a submit button for Components Table
        ag_table_submit_button = st.button(label="Generate Attack Goals Table")

        # If the Generate Attack Goals Table button is clicked and the user has provided an application description
        if ag_table_submit_button and app_input:
            # Generate the prompt using the create_prompt function
            ag_prompt = create_attack_goals_prompt(app_input)

            # Show a spinner while generating the ag table
            with st.spinner("Generating attack goals..."):
                try:
                    # Call one of the ag functions with the generated prompt
                    #if model_provider == "OpenAI API":
                    model_output = get_threat_model(openai_api_key, ag_prompt)
                                    
                    # Access the ag from parsed content
                    
                    ag_table = model_output.get("ag_table", [])
                    
                    # Save the ag table to the session state for later use in mitigations
                    st.session_state['ag_table'] = ag_table

                    # Convert the component table JSON to Markdown
                    markdown_output = json_to_markdown_ag(ag_table)
                    

                    # Display the component table in Markdown
                    st.markdown(markdown_output)

                except Exception as e:
                    st.error(f"Error generating attack goals table: {e}")

                # Add a button to allow the user to download the output as a Markdown file
                st.download_button(
                    label="Download Attack Goals Table",
                    data=markdown_output,  # Use the Markdown output
                    file_name="ag_tables.md",
                    mime="text/markdown",
                )

        # If the submit button is clicked and the user has not provided an application description
        if ag_table_submit_button and not app_input:
            st.error("Please enter your application details before submitting.")
            
     # ------------------ Controls Table Generation ------------------ #
    with st.expander("Controls", expanded=False):
        # Create a submit button for Controls Table
        controls_table_submit_button = st.button(label="Generate Controls Table")

        # If the Generate Controls Table button is clicked and the user has provided an application description
        if controls_table_submit_button and app_input:
            # Generate the prompt using the create_prompt function
            controls_prompt = create_controls_prompt(app_input)

            # Show a spinner while generating the ag table
            with st.spinner("Generating controls..."):
                try:
                    # Call one of the ag functions with the generated prompt
                    #if model_provider == "OpenAI API":
                    model_output = get_threat_model(openai_api_key, controls_prompt)
                                    
                    # Access the ag from parsed content
                    
                    controls_table = model_output.get("controls_table", [])
              
                    # Save the ag table to the session state for later use in mitigations
                    st.session_state['controls_table'] = controls_table

                    # Convert the component table JSON to Markdown
                    markdown_output = json_to_markdown_controls(controls_table)
                    

                    # Display the component table in Markdown
                    st.markdown(markdown_output)

                except Exception as e:
                    st.error(f"Error generating controls table: {e}")

                # Add a button to allow the user to download the output as a Markdown file
                st.download_button(
                    label="Download Controls Table",
                    data=markdown_output,  # Use the Markdown output
                    file_name="controls_tables.md",
                    mime="text/markdown",
                )

        # If the submit button is clicked and the user has not provided an application description
        if controls_table_submit_button and not app_input:
            st.error("Please enter your application details before submitting.")

     # ------------------ Attackers Table Generation ------------------ #
    with st.expander("Attackers", expanded=False):
        # Create a submit button for Attackers Table
        attackers_table_submit_button = st.button(label="Generate Attackers Table")

        # If the Generate Attackers Table button is clicked and the user has provided an application description
        if attackers_table_submit_button and app_input:
            # Generate the prompt using the create_prompt function
            attackers_prompt = create_attackers_prompt(app_input)

            # Show a spinner while generating the attackers table
            with st.spinner("Generating attackers..."):
                try:
                    # Call one of the attackers functions with the generated prompt
                   #if model_provider == "OpenAI API":
                    model_output = get_threat_model(openai_api_key, attackers_prompt)
                                    
                    # Access the attackers from parsed content
                    
                    attackers_table = model_output.get("attackers_table", [])
              
                    # Save the attackers table to the session state for later use in mitigations
                    st.session_state['attackers_table'] = attackers_table

                    # Convert the attackers table JSON to Markdown
                    markdown_output = json_to_markdown_attackers(attackers_table)
                    

                    # Display the component table in Markdown
                    st.markdown(markdown_output)

                except Exception as e:
                    st.error(f"Error generating attackers table: {e}")

                # Add a button to allow the user to download the output as a Markdown file
                st.download_button(
                    label="Download Attackers Table",
                    data=markdown_output,  # Use the Markdown output
                    file_name="attackers_tables.md",
                    mime="text/markdown",
                )

        # If the submit button is clicked and the user has not provided an application description
        if attackers_table_submit_button and not app_input:
            st.error("Please enter your application details before submitting.")
            
      # ------------------ Attack Surfaces Table Generation ------------------ #
    with st.expander("Attack Surfaces", expanded=False):
        # Create a submit button for Attack Surfaces Table
        surfaces_table_submit_button = st.button(label="Generate Attack Surfaces Table")

        # If the Generate Attack Surfaces Table button is clicked and the user has provided an application description
        if surfaces_table_submit_button and app_input:
            # Generate the prompt using the create_prompt function
            surfaces_prompt = create_surfaces_prompt(app_input)

            # Show a spinner while generating the attack surfaces table
            with st.spinner("Generating attack surfaces..."):
                try:
                    # Call one of the attack surfaces functions with the generated prompt
                    #if model_provider == "OpenAI API":
                    model_output = get_threat_model(openai_api_key, surfaces_prompt)
                                    
                    # Access the attack surfaces from parsed content
                    
                    surfaces_table = model_output.get("surfaces_table", [])
              
                    # Save the attack surfaces table to the session state for later use in mitigations
                    st.session_state['surfaces_table'] = surfaces_table

                    # Convert the attack surfaces table JSON to Markdown
                    markdown_output = json_to_markdown_surfaces(surfaces_table)
                    

                    # Display the component table in Markdown
                    st.markdown(markdown_output)

                except Exception as e:
                    st.error(f"Error generating attack surfaces table: {e}")

                # Add a button to allow the user to download the output as a Markdown file
                st.download_button(
                    label="Download Attack Surfaces Table",
                    data=markdown_output,  # Use the Markdown output
                    file_name="attack_surfaces_tables.md",
                    mime="text/markdown",
                )

        # If the submit button is clicked and the user has not provided an application description
        if surfaces_table_submit_button and not app_input:
            st.error("Please enter your application details before submitting.")
            
      # ------------------ Traceability Matrix Table Generation ------------------ #
    with st.expander("Traceability Matrix", expanded=False):
        # Create a submit button for trace matrix Table
        matrix_table_submit_button = st.button(label="Generate Traceability Matrix Table")

        # If the Generate Traceability Matrix Table button is clicked and the user has provided an application description
        #st.write(app_input)
        if matrix_table_submit_button and app_input:
            # Generate the prompt using the create_prompt function
            matrix_prompt = create_trace_matrix_prompt(app_input)

            # Show a spinner while generating the trace matrix table
            with st.spinner("Generating traceability matrix..."):
                try:
                    # Call one of the trace matrix functions with the generated prompt
                    #if model_provider == "OpenAI API":
                    model_output = get_threat_model(openai_api_key, matrix_prompt)
                                    
                    # Access the attack surfaces from parsed content
                    
                    trace_matrix_table = model_output.get("trace_matrix_table", [])
              
                    # Save the trace matrix table to the session state for later use in mitigations
                    st.session_state['trace_matrix_table'] = trace_matrix_table

                    # Convert the trace matrix table JSON to Markdown
                    markdown_output = json_to_markdown_matrix(trace_matrix_table)
                    

                    # Display the component table in Markdown
                    st.markdown(markdown_output)

                except Exception as e:
                    st.error(f"Error generating traceability matrix table: {e}")

                # Add a button to allow the user to download the output as a Markdown file
                st.download_button(
                    label="Download Traceability Matrix Table",
                    data=markdown_output,  # Use the Markdown output
                    file_name="trace_matrix_tables.md",
                    mime="text/markdown",
                )

        # If the submit button is clicked and the user has not provided an application description
        if matrix_table_submit_button and not app_input:
            st.error("Please enter your application details before submitting.")
