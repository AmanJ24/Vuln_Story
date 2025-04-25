#!/usr/bin/env python3
"""
Vulnerability Story Teller - Main Application

This script coordinates the parsing of vulnerability scan results,
story generation with AWA LLM, and report generation in HTML/PDF formats.
It can run as a Command Line Interface (CLI) or a simple Web Application.
"""

import os
import sys
import argparse
import logging
import json
import datetime
from typing import Dict, List, Any, Optional
import tempfile

# Configure logging
# Set level to INFO by default, can be overridden by --debug flag
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# --- Internal Module Imports ---
try:
    from parsers.burp_parser import parse_burp_xml
    # Import tenacity's RetryError to catch it specifically
    from tenacity import RetryError
    # Import StoryGenerator and its custom exceptions
    from ai_engine.storygen import StoryGenerator, APIKeyError, RateLimitError, APIError
except ImportError as e:
    logger.error(f"Error importing required internal modules: {str(e)}")
    logger.error("Please ensure you are running the script from the project's root directory "
                 "and all necessary files (parsers/burp_parser.py, ai_engine/storygen.py) exist.")
    sys.exit(1)

# --- External Module Imports ---
try:
    import pdfkit
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    from flask import Flask, request, render_template, send_file, redirect, url_for, flash
    import requests # Need requests here for exception handling from storygen
except ImportError as e:
    missing_module = str(e).split("'")[-2] # Attempt to guess the missing module
    logger.error(f"Error importing external dependency: {missing_module}")
    logger.error("Please ensure all required packages are installed.")
    logger.error("Run: pip install -r requirements.txt")
    sys.exit(1)

# --- Constants ---
DEFAULT_OUTPUT_DIR = "reports"
TEMPLATE_DIR = "templates"
WEB_TEMPLATE_DIR = "templates" # Can be the same or different if needed
DEFAULT_MODEL = "Meta-Llama-3-8B-Instruct" # Example: Changed default model
CLI_MODE = "cli"
WEB_MODE = "web"

# --- Argument Parser Setup ---
def setup_arg_parser() -> argparse.ArgumentParser:
    """Set up the command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Vulnerability Story Teller: Generate human-readable reports from vulnerability scan results using AI.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Show defaults in help message
    )

    # Mode Selection
    parser.add_argument(
        "-m", "--mode",
        choices=[CLI_MODE, WEB_MODE],
        default=CLI_MODE,
        help="Mode to run the application in: 'cli' for command-line or 'web' for a web interface."
    )

    # --- CLI Mode Arguments ---
    cli_group = parser.add_argument_group('CLI Mode Options')
    cli_group.add_argument(
        "-i", "--input",
        help="Path to the input vulnerability scan file (e.g., Burp Suite XML)."
             " Required in CLI mode."
    )
    cli_group.add_argument(
        "-o", "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to save the generated reports."
    )
    cli_group.add_argument(
        "-f", "--format",
        choices=["html", "pdf", "both"],
        default="both",
        help="Output report format(s)."
    )

    # --- Web Mode Arguments ---
    web_group = parser.add_argument_group('Web Mode Options')
    web_group.add_argument(
        "-p", "--port",
        type=int,
        default=5000,
        help="Port to run the web server on."
    )
    web_group.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host address to bind the web server to (use '0.0.0.0' to make accessible on network)."
    )

    # --- Common Arguments (Both Modes) ---
    common_group = parser.add_argument_group('Common Options')
    common_group.add_argument(
        "--api-key",
        help="Awan LLM API key. If not provided, the script will try to use the "
             "AWA_API_KEY environment variable."
    )
    common_group.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="Awan LLM model to use for generating vulnerability explanations."
             " (e.g., 'Meta-Llama-3-8B-Instruct', 'Mistral-7B-Instruct-v0.2', etc.)"
    )
    common_group.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging for more detailed output."
    )

    return parser

# --- Utility Functions ---
def ensure_output_dir(output_dir: str) -> None:
    """Ensure the output directory exists, creating it if necessary."""
    try:
        os.makedirs(output_dir, exist_ok=True)
        logger.debug(f"Ensured output directory exists: {output_dir}")
    except OSError as e:
        logger.error(f"Failed to create output directory '{output_dir}': {e}")
        raise # Re-raise the exception to halt execution if dir creation fails

def sanitize_filename(name: str) -> str:
    """Remove potentially problematic characters for filenames."""
    # Remove or replace characters invalid in filenames on most systems
    name = name.replace(' ', '_').replace('/', '_').replace('\\', '_').replace(':', '_')
    # Keep only alphanumeric, underscore, hyphen, dot
    name = "".join(c for c in name if c.isalnum() or c in ('_', '-', '.'))
    # Truncate if too long
    return name[:100]

# --- Report Generation Logic ---
def generate_report_html(vulnerabilities: List[Dict[str, Any]], report_date: str, template_dir: str = TEMPLATE_DIR) -> str:
    """
    Generate the HTML report content using Jinja2 template.

    Args:
        vulnerabilities: List of vulnerability dictionaries, including the 'story'.
        report_date: Timestamp string for the report generation date.
        template_dir: Directory containing the Jinja2 templates.

    Returns:
        Generated HTML report as a string.

    Raises:
        Exception: If template loading or rendering fails.
    """
    try:
        # Set up Jinja2 environment
        env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml']) # Enable autoescaping for security
        )
        template = env.get_template('report_template.html') # Ensure this filename matches your template

        # Render the template with vulnerability data and report date
        report_html = template.render(
            vulns=vulnerabilities,
            report_date=report_date
        )
        logger.debug("HTML report content generated successfully.")
        return report_html

    except Exception as e:
        logger.error(f"Error generating HTML report using template in '{template_dir}': {e}", exc_info=True)
        raise # Re-raise to indicate failure

def generate_reports(vulnerabilities: List[Dict[str, Any]], output_dir: str, formats: List[str]) -> Dict[str, str]:
    """
    Generate reports in the specified formats (HTML, PDF) and save them.

    Args:
        vulnerabilities: List of processed vulnerability dictionaries.
        output_dir: Directory where reports will be saved.
        formats: List containing 'html' and/or 'pdf'.

    Returns:
        Dictionary mapping format ('html', 'pdf') to the full path of the generated report file.
        Returns an empty dictionary if no formats are requested or generation fails early.
    """
    # Ensure the output directory exists before proceeding
    ensure_output_dir(output_dir)

    # Generate a unique timestamp for report filenames
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    report_paths = {}
    html_content = None
    html_path = None

    try:
        # Generate HTML content first, as it's needed for PDF generation too
        if "html" in formats or "pdf" in formats:
            report_date_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            logger.info("Generating HTML report content...")
            html_content = generate_report_html(vulnerabilities, report_date_str, TEMPLATE_DIR)

            # Save HTML file if requested
            if "html" in formats:
                html_filename = f"vulnerability_report_{timestamp}.html"
                html_path = os.path.join(output_dir, html_filename)
                try:
                    with open(html_path, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                    logger.info(f"HTML report saved successfully: {html_path}")
                    report_paths['html'] = html_path
                except IOError as e:
                    logger.error(f"Failed to save HTML report to {html_path}: {e}")
                    # Continue to PDF generation if possible, but don't add HTML to report_paths

        # Generate PDF report if requested (requires HTML content)
        if "pdf" in formats:
            if html_content is None:
                 logger.warning("Skipping PDF generation because HTML content could not be generated.")
                 return report_paths # Return paths generated so far (might be empty)

            pdf_filename = f"vulnerability_report_{timestamp}.pdf"
            pdf_path = os.path.join(output_dir, pdf_filename)
            logger.info(f"Generating PDF report: {pdf_path}...")

            # Configure pdfkit options (optional, adjust as needed)
            options = {
                'enable-local-file-access': None, # Important for rendering local CSS/images if linked
                'quiet': '' # Suppress wkhtmltopdf output unless errors occur
            }

            try:
                 # Use from_string if HTML wasn't saved, otherwise from_file is slightly preferred
                if html_path and os.path.exists(html_path):
                     logger.debug(f"Generating PDF from saved HTML file: {html_path}")
                     pdfkit.from_file(html_path, pdf_path, options=options)
                else:
                     logger.debug("Generating PDF from HTML string content.")
                     pdfkit.from_string(html_content, pdf_path, options=options)

                logger.info(f"PDF report saved successfully: {pdf_path}")
                report_paths['pdf'] = pdf_path

            except OSError as e:
                 # Catch errors specifically related to wkhtmltopdf execution
                 logger.error(f"Error generating PDF report: {e}")
                 logger.error("This often means 'wkhtmltopdf' is not installed or not found in the system's PATH.")
                 logger.error("Please install it from https://wkhtmltopdf.org/downloads.html or via your package manager (e.g., 'sudo apt-get install wkhtmltopdf').")
                 # PDF generation failed, but report_paths might still contain HTML path
            except Exception as e:
                 logger.error(f"An unexpected error occurred during PDF generation: {e}", exc_info=True)
                 # PDF generation failed

        return report_paths

    except Exception as e:
        # Catch errors from ensure_output_dir or generate_report_html
        logger.error(f"Fatal error during report generation process: {e}", exc_info=True)
        # Return whatever paths might have been generated before the error
        return report_paths


# --- Core Processing Logic ---
def process_file(input_file: str, output_dir: str, formats: List[str], api_key: Optional[str] = None, model: str = DEFAULT_MODEL) -> Dict[str, str]:
    """
    Orchestrates the entire process: parse file, generate stories, generate reports.

    Args:
        input_file: Path to the input vulnerability scan file (e.g., Burp XML).
        output_dir: Directory to save the generated reports.
        formats: List of desired output formats ('html', 'pdf').
        api_key: Awan LLM API key (optional, uses environment variable if None).
        model: Awan LLM model name to use.

    Returns:
        Dictionary mapping format type ('html', 'pdf') to the generated report file path.

    Raises:
        FileNotFoundError: If the input file does not exist.
        ValueError: If StoryGenerator initialization fails (e.g., no API key).
        Exception: For other critical errors during parsing or processing.
    """
    processed_vulns = [] # Store vulnerabilities along with their generated stories or errors

    try:
        # Step 1: Parse the vulnerability scan file
        logger.info(f"Parsing vulnerability scan file: {input_file}")
        vulnerabilities = parse_burp_xml(input_file) # This raises FileNotFoundError if file doesn't exist
        logger.info(f"Successfully parsed {len(vulnerabilities)} vulnerabilities from the input file.")

        if not vulnerabilities:
            logger.warning("No vulnerabilities found in the input file. Generating an empty report.")
            # Call generate_reports with an empty list to create an empty report structure
            report_paths = generate_reports([], output_dir, formats)
            return report_paths

        # Step 2: Initialize Story Generator
        logger.info("Initializing AI Story Generator...")
        # StoryGenerator constructor now raises ValueError if API key is missing
        story_generator = StoryGenerator(api_key=api_key, model=model)
        logger.info(f"Story Generator initialized using model: {story_generator.model}")

        # Step 3: Generate stories for each vulnerability
        logger.info("Generating AI explanations for each vulnerability...")
        total_vulns = len(vulnerabilities)

        for i, vuln in enumerate(vulnerabilities):
            # Create a concise identifier for logging purposes
            vuln_id_for_log = f"'{vuln.get('issue', 'Unknown Issue')[:40]}' ({i+1}/{total_vulns})"
            logger.info(f"Processing {vuln_id_for_log}...")

            processed_vuln = vuln.copy() # Work on a copy to avoid modifying the original list directly

            try:
                # Attempt to generate the story using the AI engine
                story = story_generator.generate_story(vuln)
                # Store the successfully generated story (HTML is safe via Jinja autoescape)
                processed_vuln['story'] = story
                logger.debug(f"Successfully generated story for {vuln_id_for_log}")

            # --- Handle specific errors from StoryGenerator ---
            except RetryError as e:
                # This catches the final error after tenacity retries have failed
                final_exception = e.last_attempt.exception()
                error_msg = f"Failed after multiple retries: {type(final_exception).__name__} - {str(final_exception)}"
                logger.error(f"Error for {vuln_id_for_log}: {error_msg}")
                processed_vuln['story'] = f"<p style='color:red; font-weight:bold;'>Story Generation Failed:</p><p style='color:red;'>{error_msg}</p>"
            except APIKeyError as e:
                error_msg = f"Invalid API Key: {str(e)}"
                logger.error(f"API Key Error for {vuln_id_for_log}: {error_msg}")
                processed_vuln['story'] = f"<p style='color:red; font-weight:bold;'>Story Generation Failed:</p><p style='color:red;'>{error_msg}</p><p>Please check your Awan LLM API key.</p>"
                # Optionally, could stop processing here if the key is definitely wrong
                # raise ValueError("Invalid API Key provided.") from e
            except RateLimitError as e:
                error_msg = f"API Rate Limit Exceeded: {str(e)}"
                logger.warning(f"Rate Limit Hit for {vuln_id_for_log}: {error_msg}")
                processed_vuln['story'] = f"<p style='color:orange; font-weight:bold;'>Story Generation Temporarily Failed:</p><p style='color:orange;'>{error_msg}</p><p>Try again later or reduce request frequency.</p>"
            except APIError as e:
                error_msg = f"API Error: {str(e)}"
                logger.error(f"API Error for {vuln_id_for_log}: {error_msg}")
                processed_vuln['story'] = f"<p style='color:red; font-weight:bold;'>Story Generation Failed:</p><p style='color:red;'>{error_msg}</p>"
            except requests.exceptions.RequestException as e:
                # Catch network/connection errors not handled by specific types above
                error_msg = f"Network/Request Error: {type(e).__name__} - {str(e)}"
                logger.error(f"Network Error for {vuln_id_for_log}: {error_msg}")
                processed_vuln['story'] = f"<p style='color:red; font-weight:bold;'>Story Generation Failed:</p><p style='color:red;'>{error_msg}</p><p>Check network connection and API endpoint.</p>"
            # --- Catch any other unexpected errors during story generation ---
            except Exception as e:
                error_msg = f"Unexpected Error: {type(e).__name__} - {str(e)}"
                logger.error(f"Unexpected error processing {vuln_id_for_log}: {error_msg}", exc_info=True) # Log traceback for debugging
                processed_vuln['story'] = f"<p style='color:red; font-weight:bold;'>Story Generation Failed:</p><p style='color:red;'>An unexpected error occurred. Please check application logs.</p>"

            # Add the processed vulnerability (with story or error message) to our list
            processed_vulns.append(processed_vuln)

        # Step 4: Generate the final reports using the processed data
        logger.info(f"Generating final reports in formats: {', '.join(formats)}...")
        report_paths = generate_reports(processed_vulns, output_dir, formats) # Use the list containing stories/errors

        return report_paths

    # Handle critical errors that prevent processing from starting/continuing
    except FileNotFoundError: # Already logged in parse_burp_xml if it happens there
        raise # Re-raise for CLI/Web handler
    except ValueError as e: # Catch errors from StoryGenerator init (e.g., missing API key)
        logger.error(f"Initialization failed: {e}")
        raise # Re-raise for CLI/Web handler
    except Exception as e:
        logger.error(f"A critical error occurred during file processing: {str(e)}", exc_info=True)
        raise # Re-raise for CLI/Web handler


# --- CLI Mode Execution ---
def run_cli_mode(args: argparse.Namespace) -> int:
    """Run the application in Command Line Interface mode."""
    logger.info("Starting Vulnerability Story Teller in CLI mode.")

    # Validate CLI-specific arguments
    if not args.input:
        logger.error("Input file is required in CLI mode. Use -i or --input.")
        parser.print_help() # Show help message
        return 1
    if not os.path.isfile(args.input):
        logger.error(f"Input file not found: {args.input}")
        return 1

    # Determine desired output formats
    formats_to_generate = []
    if args.format == "html":
        formats_to_generate = ["html"]
    elif args.format == "pdf":
        formats_to_generate = ["pdf"]
    else: # 'both'
        formats_to_generate = ["html", "pdf"]

    try:
        # Start the core processing logic
        report_paths = process_file(
            input_file=args.input,
            output_dir=args.output_dir,
            formats=formats_to_generate,
            api_key=args.api_key, # Pass from args
            model=args.model      # Pass from args
        )

        # Report results to the user
        if not report_paths:
            logger.warning("Processing completed, but no reports were generated (this might be due to errors or no vulnerabilities found).")
            return 1 # Indicate potential issue
        else:
            print("\n--- Report Generation Complete ---")
            for format_type, path in report_paths.items():
                print(f"- {format_type.upper()} report saved to: {path}")
            print("---------------------------------")
            return 0 # Indicate success

    except FileNotFoundError:
        # Error already logged by process_file or validation
        print("\nError: Input file not found. Please check the path.", file=sys.stderr)
        return 1
    except ValueError as e:
        # Error from StoryGenerator init (likely API key)
        print(f"\nError: Initialization failed - {e}", file=sys.stderr)
        return 1
    except Exception as e:
        # Catch any other critical exceptions bubbled up from process_file
        print(f"\nAn unexpected critical error occurred: {e}", file=sys.stderr)
        logger.error("Critical error during CLI execution.", exc_info=True) # Log traceback
        return 1

# --- Web Mode Execution ---
# Global variable to store generated report paths for download in web mode
# Note: This is simple state management suitable for single-user or low-traffic scenarios.
# For production, consider more robust state management (e.g., sessions, database).
web_generated_reports: Dict[str, str] = {}

def create_web_app(api_key_arg: Optional[str], model_arg: str, output_dir_arg: str) -> Flask:
    """Create and configure the Flask web application instance."""
    app = Flask(__name__, template_folder=WEB_TEMPLATE_DIR)
    # Simple secret key for flashing messages (replace with a real secret in production)
    app.secret_key = os.urandom(24)

    # Store config for use within routes (avoids relying solely on global args)
    app.config['API_KEY'] = api_key_arg
    app.config['MODEL'] = model_arg
    app.config['OUTPUT_DIR'] = output_dir_arg

    @app.route('/')
    def index():
        """Render the main upload page."""
        # Clear previous results when returning to the index
        global web_generated_reports
        web_generated_reports = {}
        return render_template('index.html')

    @app.route('/upload', methods=['POST'])
    def upload_and_process():
        """Handle file upload, process it, and show results page."""
        global web_generated_reports
        web_generated_reports = {} # Clear previous results

        if 'file' not in request.files:
            flash("No file part in the request.", "error")
            return redirect(url_for('index'))

        file = request.files['file']
        if file.filename == '':
            flash("No file selected for uploading.", "error")
            return redirect(url_for('index'))

        # Basic validation for file type (can be enhanced)
        if not file.filename.lower().endswith('.xml'):
            flash("Invalid file type. Please upload a Burp Suite XML file.", "error")
            return redirect(url_for('index'))

        # Determine requested formats from the form
        selected_formats = request.form.getlist('formats')
        if not selected_formats:
             flash("Please select at least one report format (HTML or PDF).", "error")
             return redirect(url_for('index'))

        # Use a temporary directory for secure file handling
        temp_dir = None
        try:
            temp_dir = tempfile.mkdtemp(prefix="vulnstory_")
            temp_file_path = os.path.join(temp_dir, sanitize_filename(file.filename))
            file.save(temp_file_path)
            logger.info(f"Uploaded file saved temporarily to: {temp_file_path}")

            # Retrieve config stored in the app object
            api_key = app.config['API_KEY']
            model = app.config['MODEL']
            output_dir = app.config['OUTPUT_DIR']

            # Call the core processing function
            generated_paths = process_file(
                input_file=temp_file_path,
                output_dir=output_dir,
                formats=selected_formats,
                api_key=api_key,
                model=model
            )

            # Store paths globally for download links
            web_generated_reports.update(generated_paths)

            if not generated_paths:
                 flash("Processing completed, but no reports were generated. Check logs for details.", "warning")
                 return render_template('result.html', reports={}) # Show result page with no links
            else:
                 flash("Report generation successful!", "success")
                 return render_template('result.html', reports=generated_paths)

        except (FileNotFoundError, ValueError, Exception) as e:
            logger.error(f"Error during web upload processing: {str(e)}", exc_info=True)
            flash(f"Error processing file: {type(e).__name__} - {str(e)}. Please check logs or try again.", "error")
            return redirect(url_for('index')) # Redirect back to upload on error

        finally:
            # Clean up the temporary file and directory
            if temp_dir and os.path.exists(temp_dir):
                try:
                    # Ensure temp_file_path exists before trying to remove
                    if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
                         os.unlink(temp_file_path)
                    os.rmdir(temp_dir)
                    logger.debug(f"Cleaned up temporary directory: {temp_dir}")
                except OSError as e:
                    logger.warning(f"Could not completely clean up temporary directory {temp_dir}: {e}")

    @app.route('/download/<format_type>')
    def download_report(format_type):
        """Provide the generated report file for download."""
        global web_generated_reports
        if format_type in web_generated_reports and os.path.exists(web_generated_reports[format_type]):
            try:
                logger.info(f"Serving file for download ({format_type}): {web_generated_reports[format_type]}")
                return send_file(
                    web_generated_reports[format_type],
                    as_attachment=True,
                    # Optional: derive filename for download from path
                    download_name=os.path.basename(web_generated_reports[format_type])
                )
            except Exception as e:
                logger.error(f"Error sending file {web_generated_reports[format_type]} for download: {e}", exc_info=True)
                flash(f"Could not download the {format_type} report. File may be missing or unreadable.", "error")
                # Render the result page again, potentially showing the error
                return render_template('result.html', reports=web_generated_reports)
        else:
            logger.warning(f"Download request for unavailable format '{format_type}' or missing file.")
            flash(f"The requested {format_type} report is not available for download.", "error")
            # Redirect back to results page, state might be lost if user navigated away
            return redirect(url_for('index')) # Or redirect to results if state handling was better

    return app

def run_web_mode(args: argparse.Namespace) -> int:
    """Run the application in Web Server mode."""
    logger.info("Starting Vulnerability Story Teller in Web mode.")
    try:
        # Ensure template directory exists
        if not os.path.isdir(WEB_TEMPLATE_DIR):
            logger.error(f"Web template directory not found: {WEB_TEMPLATE_DIR}")
            print(f"\nError: Web template directory '{WEB_TEMPLATE_DIR}' not found.", file=sys.stderr)
            return 1

        # Ensure output directory exists (Flask won't create it automatically for reports)
        ensure_output_dir(args.output_dir)

        # Create the Flask app instance, passing necessary config
        app = create_web_app(
            api_key_arg=args.api_key,
            model_arg=args.model,
            output_dir_arg=args.output_dir
        )

        # Run the Flask development server
        print(f"\n* Vulnerability Story Teller Web Interface *")
        print(f"* Running on http://{args.host}:{args.port}")
        print(f"* Output directory for reports: {os.path.abspath(args.output_dir)}")
        print(f"* Using AI model: {args.model}")
        print(f"* Debug mode: {'On' if args.debug else 'Off'}")
        print(f"* Press CTRL+C to quit")

        # Setting debug=True enables auto-reloading and Werkzeug debugger (use False in production)
        app.run(host=args.host, port=args.port, debug=args.debug)

        return 0 # Typically returns 0 unless server fails catastrophically at startup

    except Exception as e:
        logger.error(f"Failed to start the web server: {str(e)}", exc_info=True)
        print(f"\nError: Failed to start the web server - {e}", file=sys.stderr)
        return 1

# --- Main Execution ---
def main() -> int:
    """Main entry point for the script."""
    # Parse command line arguments
    parser = setup_arg_parser()
    args = parser.parse_args()

    # Set logging level based on --debug flag
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled.")
    else:
        logging.getLogger().setLevel(logging.INFO)

    # Log the mode of operation
    logger.info(f"Selected mode: {args.mode}")

    # Execute the chosen mode
    if args.mode == CLI_MODE:
        return run_cli_mode(args)
    elif args.mode == WEB_MODE:
        return run_web_mode(args)
    else:
        # This case should not be reachable due to argparse 'choices'
        logger.error(f"Invalid mode selected: {args.mode}")
        parser.print_help()
        return 1

# --- Script Execution Guard ---
if __name__ == "__main__":
    # Exit with the status code returned by the main function
    sys.exit(main())