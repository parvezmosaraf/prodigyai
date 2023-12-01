from django.shortcuts import render, HttpResponseRedirect
from .models import CV
import PyPDF2
import openai
import concurrent.futures
from itertools import repeat
import re
from django.contrib.auth.decorators import login_required
from decouple import config

# Set your OpenAI API key
openai.api_key = config('OPENAI_API_KEY')

# def extract_text_from_pdf_bulk(cv_paths):
#     texts = []
#     for pdf_path in cv_paths:
#         try:
#             with open(pdf_path, 'rb') as file:
#                 pdf_reader = PyPDF2.PdfReader(file)
#                 text = ''
#                 for page_num in range(len(pdf_reader.pages)):
#                     page_text = pdf_reader.pages[page_num].extract_text()
#                     if isinstance(page_text, str):  # Check if the extracted text is a string
#                         text += page_text
#                 texts.append(text.lower())
#         except Exception as e:
#             print(f"Error extracting text from {pdf_path}: {e}")
#             texts.append('')
#     return texts
def extract_text_from_pdf_bulk(cv_paths):
    texts = []
    for pdf_path in cv_paths:
        try:
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                text = ''
                for page_num in range(len(pdf_reader.pages)):
                    page_text = pdf_reader.pages[page_num].extract_text()
                    if isinstance(page_text, str):  # Check if the extracted text is a string
                        text += page_text
                texts.append(text.lower())
        except Exception as e:
            print(f"Error extracting text from {pdf_path}: {e}")
            texts.append('')
    return texts

def analyze_text(text_to_analyze):
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "Extract Information From CV & [NAME]\n\n [EMAIL]\n\n[PREVIOUS JOB]\n\n[LOCATION/ADDRESS]\n\n[PHONE NO/MOBILE NO/CELL NO/ CONTACT NO]"},
            {"role": "user", "content": text_to_analyze}
        ],
        max_tokens=100
        # Add any other parameters you need
    )
    return response.choices[0].message["content"]



import re
import openai

def separate_details(text_to_analyze):
    extracted_details = {
        'email': None,
        'name': None,
        'location': None,
        'previous_job': None,
        'phone': None
    }

    # Define patterns for extraction using regular expressions
    email_pattern = r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
    name_pattern = r"Name: ([^\n]+)"
    location_pattern = r"(?:Location|Address): ([^\n]+)"
    prev_job_pattern = r"Previous Job: ([^\n]+)"

    # Extract details using regex patterns
    extracted_details['email'] = re.search(email_pattern, text_to_analyze).group(1) if re.search(email_pattern, text_to_analyze) else None
    extracted_details['name'] = re.search(name_pattern, text_to_analyze).group(1) if re.search(name_pattern, text_to_analyze) else None
    extracted_details['location'] = re.search(location_pattern, text_to_analyze).group(1) if re.search(location_pattern, text_to_analyze) else None
    extracted_details['previous_job'] = re.search(prev_job_pattern, text_to_analyze).group(1) if re.search(prev_job_pattern, text_to_analyze) else None


    return extracted_details







from itertools import zip_longest

def search_pdf(request):
    if request.method == 'POST':
        keyword = request.POST.get('keyword').lower()
        
        all_cvs = CV.objects.all()
        cv_paths = [cv.cv.path for cv in all_cvs]

        # Extract text from PDFs in bulk
        texts = extract_text_from_pdf_bulk(cv_paths)

        relevant_cvs = []
        irrelevant_cvs = []
        analyzed_texts = []
        with concurrent.futures.ThreadPoolExecutor() as executor:
            analyzed_texts = list(executor.map(analyze_text, texts))

        for cv, analyzed_text in zip_longest(all_cvs, analyzed_texts):
            if analyzed_text:
                extracted_details = separate_details(analyzed_text)
                if keyword in analyzed_text.lower():
                    relevant_cvs.append({'cv': cv, 'extracted_details': extracted_details})
                else:
                    irrelevant_cvs.append({'cv': cv, 'extracted_details': extracted_details})

        return render(request, 'result.html', {'relevant_cvs': relevant_cvs, 'irrelevant_cvs': irrelevant_cvs, 'keyword': keyword})
    
    return render(request, 'result.html')




def cv_form(request):
    if request.method == 'POST' and 'cv' in request.FILES:
        cv_file = request.FILES['cv']
        cv_database = CV(cv=cv_file)
        cv_database.save()
        return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
@login_required
def home(request):
    cv = CV.objects.all()
    return render(request, "index.html", {'cv': cv})






from django.shortcuts import render
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Function to authenticate and get Gmail service
def get_gmail_service(oauth_token):
    creds = Credentials(oauth_token)
    return build('gmail', 'v1', credentials=creds)

# Function to search for emails with attachments containing a specific keyword
def search_emails_with_attachments(service, keyword):
    try:
        response = service.users().messages().list(userId='me', q=f"{keyword} has:attachment").execute()
        messages = response.get('messages', [])

        attachments = []

        for message in messages:
            msg_id = message['id']
            message = service.users().messages().get(userId='me', id=msg_id).execute()

            for part in message['payload']['parts']:
                if part.get('filename'):
                    attachment = service.users().messages().attachments().get(
                        userId='me', messageId=msg_id, id=part['body']['attachmentId']
                    ).execute()
                    attachments.append(attachment)

        return attachments

    except HttpError as error:
        print(f"An error occurred: {error}")
        return None

# Your view function to handle the request
def search_attachments(request):
    if request.method == 'POST':
        keyword = request.POST.get('keyword')
        oauth_token = request.session.get('oauth_token')  # Retrieve OAuth token from session

        if oauth_token:
            # Authenticate and get Gmail service
            service = get_gmail_service(oauth_token)

            # Search for emails with attachments based on the keyword
            attachments = search_emails_with_attachments(service, keyword)

            if attachments is not None:
                # Process retrieved attachments (e.g., display, save to database, etc.)
                return render(request, 'attachments.html', {'attachments': attachments})
            else:
                return render(request, 'error.html', {'error_message': 'An error occurred while fetching attachments.'})

    return render(request, 'index.html')  # Render search template for entering keyword






































from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.models import User

def signin(request):
    if request.method == 'POST':
        name = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=name, password=password)
        if user is not None:
            login(request, user)
            return redirect('/')
        else:
            messages.error(request, 'Email or Password incorrect')

    return render(request, 'signin.html')


def signup(request):
    if request.method == "POST":
        first_name = request.POST['first_name']
        if first_name == "":
            messages.error(request, "You must enter Fisrt Name")
            return render(request, 'signup.html')
        last_name = request.POST['last_name']
        if last_name == "":
            messages.error(request, "You must enter Last Name")
            return render(request, 'signup.html')
        username = request.POST['username']
        if username == "":
            messages.error(request, "You must enter Username")
            return render(request, 'signup.html')
        email = request.POST['email']
        if email == "":
            messages.error(request, "You must enter Email")
            return render(request, 'signup.html')
        password = request.POST['password']
        if password == "":
            messages.error(request, "You must enter Password")
            return render(request, 'signup.html')
        confirm_password = request.POST['confirm_password']
        if password == confirm_password:
            if User.objects.filter(username=username).exists():
                messages.error(request, "Username already taken")
            elif User.objects.filter(email=email).exists():
                messages.error(request, "Email already taken")

            else:
                    user = User.objects.create_user(
                        first_name=first_name, last_name=last_name, username=username, password=password, email=email)
                    user.save()
                    login(request, user)
                    return redirect('/')


        else:
            messages.error(request, 'Password not matched')

    return render(request, 'signup.html')


def signout(request):
    logout(request)
    return redirect("/")

