#!/usr/bin/env python3
"""
Story Generator Module for Vulnerability Story Teller.
This module uses AWA LLM to generate human-readable explanations of vulnerabilities.
"""

import os
import time
import logging
import json
from typing import Dict, Any, Optional, List, Union
import requests
# Import RetryError to catch it specifically if needed later
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, RetryError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Default API key environment variable name
DEFAULT_API_KEY_ENV = "AWA_API_KEY"

# Define specific exceptions we might want to handle differently if needed
class APIKeyError(Exception):
    """Custom exception for invalid API key errors (401)."""
    pass

class RateLimitError(Exception):
    """Custom exception for rate limit errors (429)."""
    pass

class APIError(Exception):
    """Custom exception for other client or server API errors."""
    pass


class StoryGenerator:
    """Class to handle AWA LLM-based story generation for vulnerabilities."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-3.5-turbo"):
        """
        Initialize the StoryGenerator.

        Args:
            api_key (str, optional): AWA LLM API key. If None, will try to get from environment.
            model (str, optional): AWA LLM model to use. Defaults to "gpt-3.5-turbo".

        Raises:
            ValueError: If API key is not provided and not found in environment.
        """
        # Get API key from parameter, environment, or raise error
        self.api_key = api_key or os.environ.get(DEFAULT_API_KEY_ENV)
        if not self.api_key:
            raise ValueError(
                f"AWA LLM API key is required. Either pass it directly via --api-key "
                f"or set the {DEFAULT_API_KEY_ENV} environment variable."
            )

        # Store model and API key for requests
        self.model = model
        logger.info(f"StoryGenerator initialized with model: {model}")
        # Basic check for key format (optional, adjust as needed)
        if not isinstance(self.api_key, str) or len(self.api_key) < 10: # Example basic check
             logger.warning("API key seems unusually short. Please verify it is correct.")


    @retry(
        # Retry on common transient errors: Timeout, ConnectionError, RateLimitError, 5xx Server Errors
        retry=retry_if_exception_type((requests.exceptions.Timeout, requests.exceptions.ConnectionError, RateLimitError, APIError)),
        stop=stop_after_attempt(5), # Number of attempts
        wait=wait_exponential(multiplier=1, min=2, max=60), # Exponential backoff
        before_sleep=lambda retry_state: logger.warning(
            # Log the actual exception causing the retry
            f"API call failed with {type(retry_state.outcome.exception()).__name__}: {retry_state.outcome.exception()}. Retrying attempt {retry_state.attempt_number + 1} in {retry_state.next_action.sleep:.2f} seconds..."
        )
    )
    def generate_story(self, vulnerability: Dict[str, Any]) -> str:
        """
        Generate a story explaining a vulnerability using the Awan LLM API.

        Args:
            vulnerability (Dict[str, Any]): Dictionary containing vulnerability details.
                                            Expected keys: 'issue', 'url', 'parameter',
                                            'severity', 'description'.

        Returns:
            str: The AI-generated story explaining the vulnerability.

        Raises:
            APIKeyError: If the API returns a 401 Unauthorized error.
            RateLimitError: If the API returns a 429 Too Many Requests error.
            APIError: For other 4xx client errors (excluding 401, 429) or 5xx server errors.
            requests.exceptions.Timeout: If the request times out.
            requests.exceptions.ConnectionError: If there's a network connection issue.
            requests.exceptions.RequestException: For other general request-related errors.
            Exception: For unexpected errors during processing or response parsing.
        """
        vuln_name = vulnerability.get('issue', 'Unknown Issue')
        vuln_url = vulnerability.get('url', 'Unknown URL')
        vuln_param = vulnerability.get('parameter', 'N/A')
        vuln_severity = vulnerability.get('severity', 'Unknown')
        # Truncate potentially very long descriptions for the prompt to avoid context limits
        raw_description = vulnerability.get('description', 'No description provided')
        vuln_description = (raw_description[:1000] + '...') if len(raw_description) > 1000 else raw_description


        logger.info(f"Generating story for: {vuln_name} at {vuln_url}")

        # Refined prompt for better structure and clarity
        prompt = f"""
You are a cybersecurity analyst writing a report section. Given this vulnerability finding:
- Vulnerability Name: {vuln_name}
- Affected URL: {vuln_url}
- Affected Parameter(s): {vuln_param}
- Severity: {vuln_severity}
- Technical Description: {vuln_description}

Please explain this vulnerability in a narrative format suitable for developers and potentially managers. Use the following structure with Markdown headings:

### How an Attacker Might Find It
Briefly describe how an attacker could discover this type of weakness (e.g., automated scanning, manual fuzzing, inspecting traffic).

### How It Can Be Exploited
Describe the general steps an attacker would take to exploit this vulnerability. Avoid overly technical jargon where possible.

### Potential Impact
Explain why this vulnerability is a problem. What are the consequences if exploited? (e.g., data theft, session hijacking, code execution, denial of service).

### Recommended Fix
Provide clear, concise recommendations on how to fix this vulnerability (e.g., use output encoding, implement input validation, update library, configure securely).

Keep the language professional but accessible.
"""

        # Awan LLM API endpoint
        url = "https://api.awanllm.com/v1/chat/completions"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}' # Use the stored API key
        }

        # Construct the payload for the API request
        payload = {
            "model": self.model, # Use the model specified during initialization
            "messages": [
                {"role": "system", "content": "You are a cybersecurity analyst specializing in explaining technical vulnerabilities clearly and concisely using a structured narrative format."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.6, # Slightly lower temperature for more focused output
            "max_tokens": 1500, # Increased slightly, monitor usage/cost
            "top_p": 0.9,
            "repetition_penalty": 1.1,
            # "presence_penalty": 0.0, # Often not needed for structured tasks
            # "frequency_penalty": 0.0, # Often not needed for structured tasks
            "stream": False # Not using streaming response for this use case
        }

        logger.debug(f"Sending request to AWA LLM API. Prompt length: {len(prompt)} chars.")
        # Avoid logging the full payload in production if the prompt contains sensitive data from the report
        # logger.debug(f"Payload: {json.dumps(payload, indent=2)}")

        try:
            # Make the POST request to the API
            response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=90) # Increased timeout

            # Check for HTTP errors explicitly after the request returns
            if not response.ok:
                status_code = response.status_code
                try:
                    # Try to get structured error details from the response body
                    error_details = response.json()
                    error_message_detail = error_details.get('error', {}).get('message', str(error_details))
                except json.JSONDecodeError:
                    # Fallback to raw text if response is not valid JSON
                    error_details = response.text
                    error_message_detail = error_details

                error_message = f"API Error {status_code}: {error_message_detail}"
                logger.error(f"Request failed for {vuln_name}: {error_message}")

                # Raise specific exceptions based on status code for better handling/retrying
                if status_code == 401:
                     # Non-retryable: API key is wrong
                    raise APIKeyError(error_message)
                elif status_code == 429:
                    # Potentially retryable: Rate limit hit
                    raise RateLimitError(error_message)
                elif 400 <= status_code < 500:
                    # Non-retryable: Other client-side errors (e.g., bad request format)
                    raise APIError(f"Client Error {status_code}: {error_message_detail}")
                elif 500 <= status_code < 600:
                    # Potentially retryable: Server-side errors
                    raise APIError(f"Server Error {status_code}: {error_message_detail}") # Let tenacity handle retry
                else:
                     # Catch-all for other unexpected HTTP errors
                     raise requests.exceptions.HTTPError(error_message, response=response)


            # If response is OK (status code 2xx)
            data = response.json()

            # Defensive coding: check the expected structure of the successful response
            if 'choices' in data and isinstance(data['choices'], list) and len(data['choices']) > 0 and \
               isinstance(data['choices'][0], dict) and 'message' in data['choices'][0] and \
               isinstance(data['choices'][0]['message'], dict) and 'content' in data['choices'][0]['message']:

                story = data['choices'][0]['message']['content'].strip()
                logger.info(f"Successfully generated story for: {vuln_name}")
                return story
            else:
                # Handle cases where the response structure is not as expected
                logger.error(f"Unexpected successful API response format for {vuln_name}: {data}")
                raise APIError(f"Unexpected API response format received: {str(data)[:200]}...") # Raise APIError

        # Handle specific request exceptions
        except requests.exceptions.Timeout as e:
            logger.error(f"AWA LLM API request timed out for {vuln_name}: {str(e)}")
            raise # Re-raise Timeout to be potentially caught by tenacity retry logic
        except requests.exceptions.ConnectionError as e:
            logger.error(f"AWA LLM API connection error for {vuln_name}: {str(e)}")
            raise # Re-raise ConnectionError for tenacity
        except requests.exceptions.RequestException as e:
            # Catch other request-related errors (e.g., invalid URL, SSL issues)
            logger.error(f"AWA LLM API request failed for {vuln_name}: {str(e)}")
            raise # Re-raise for tenacity or upstream handling

        # Handle errors during response processing (e.g., JSON parsing of success response, key access)
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as e:
            logger.error(f"Error processing successful API response for {vuln_name}: {str(e)}")
            # Treat response processing errors as potentially transient API issues
            raise APIError(f"Error processing API response: {str(e)}")

        # Catch any other unexpected errors during the function execution
        except Exception as e:
            logger.error(f"An unexpected error occurred during story generation for {vuln_name}: {type(e).__name__} - {str(e)}", exc_info=True)
            raise # Re-raise the original unexpected exception


    # --- Batch generation (Optional Enhancement) ---
    # The current main.py calls generate_story individually. If you need higher throughput,
    # you could implement true parallel/async processing here later.
    # For now, a simple sequential wrapper might look like this (but it's not used by main.py as written).
    def generate_stories_batch_sequential(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Generate stories for multiple vulnerabilities sequentially with delays.

        Args:
            vulnerabilities (List[Dict[str, Any]]): List of vulnerability data

        Returns:
            Dict[str, str]: Dictionary mapping vulnerability unique IDs to generated stories or error messages
        """
        results = {}
        total_vulns = len(vulnerabilities)
        logger.info(f"Processing batch of {total_vulns} vulnerabilities sequentially...")

        for i, vuln in enumerate(vulnerabilities):
            # Create a relatively unique ID for logging/results
            vuln_id_for_log = f"{vuln.get('issue', 'unknown')[:30]} ({i+1}/{total_vulns})"
            logger.info(f"Processing batch item: {vuln_id_for_log}")

            try:
                story = self.generate_story(vuln)
                results[vuln_id_for_log] = story # Use the log ID as key

                # Simple delay to help avoid rate limits when processing many items sequentially
                if i < total_vulns - 1:
                    time.sleep(1.5) # Adjust sleep time based on observed API limits (e.g., 1-2 seconds)

            # Catch RetryError specifically if tenacity fails after all attempts
            except RetryError as e:
                final_exception = e.last_attempt.exception()
                error_msg = f"Story generation failed for {vuln_id_for_log} after multiple retries: {type(final_exception).__name__}: {final_exception}"
                logger.error(error_msg)
                results[vuln_id_for_log] = error_msg # Store the informative error
            # Catch specific API errors defined earlier
            except (APIKeyError, RateLimitError, APIError) as e:
                error_msg = f"Story generation failed for {vuln_id_for_log}: {type(e).__name__}: {str(e)}"
                logger.error(error_msg)
                results[vuln_id_for_log] = error_msg
            # Catch broader request exceptions
            except requests.exceptions.RequestException as e:
                error_msg = f"Story generation failed for {vuln_id_for_log} due to network/request issue: {type(e).__name__}: {str(e)}"
                logger.error(error_msg)
                results[vuln_id_for_log] = error_msg
            # Catch any other exceptions during generation for this specific vulnerability
            except Exception as e:
                error_msg = f"Unexpected error generating story for {vuln_id_for_log}: {type(e).__name__}: {str(e)}"
                logger.error(error_msg, exc_info=True) # Log traceback for unexpected errors
                results[vuln_id_for_log] = error_msg

        logger.info(f"Completed sequential batch processing. Processed {len(results)} vulnerabilities.")
        return results


# Example usage block for direct testing (optional)
if __name__ == "__main__":
    print("Testing StoryGenerator module...")
    # Requires AWA_API_KEY environment variable to be set for direct execution
    if not os.environ.get(DEFAULT_API_KEY_ENV):
        print(f"Error: Please set the {DEFAULT_API_KEY_ENV} environment variable to test.")
        sys.exit(1)

    # Example vulnerability data (replace with your actual test data or load from file)
    sample_vuln = {
        'host': 'http://testphp.vulnweb.com',
        'url': 'http://testphp.vulnweb.com/search.php?q=<script>alert(1)</script>',
        'issue': 'Reflected Cross-site scripting (XSS)',
        'severity': 'High',
        'description': 'The application echoes input from the q parameter back to the user without proper sanitization or output encoding, allowing script injection.',
        'parameter': 'q',
        'request': 'GET /search.php?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\nHost: testphp.vulnweb.com',
        'response': 'HTTP/1.1 200 OK\nContent-Type: text/html\n\n... <input value="<script>alert(1)</script>"> ...'
    }

    try:
        print("Initializing StoryGenerator...")
        # You can override the model here if needed: story_gen = StoryGenerator(model="your-preferred-model")
        story_gen = StoryGenerator()

        print(f"\nGenerating story for: {sample_vuln['issue']}")
        story = story_gen.generate_story(sample_vuln)
        print("\n=== Generated Story ===")
        print(story)
        print("=======================\n")

        print("Test completed successfully.")

    except ValueError as e:
        print(f"Initialization Error: {e}")
    except RetryError as e:
        print(f"API Error after retries: {e.last_attempt.exception()}")
    except (APIKeyError, RateLimitError, APIError, requests.exceptions.RequestException) as e:
        print(f"API/Request Error: {type(e).__name__} - {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {type(e).__name__} - {e}")
        import traceback
        traceback.print_exc()