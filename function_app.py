# pip install azure-identity
# pip install azure-communication-identity
# pip install azure-communication-email

import os
import time
import json
import csv
import urllib.request
import urllib.parse

import datetime
import logging
import azure.functions as func

import base64
from azure.communication.email import EmailClient

# from azure.identity import DefaultAzureCredential
# To use Azure Active Directory Authentication (DefaultAzureCredential) make sure to have AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET as env variables.



# define environment variables and other fixed parameters
tenantId = os.environ.get('azure_tenant_id')
appId = os.environ.get('defender_app_id')
appSecret = os.environ.get('defender_app_secret')
sumourl = os.environ.get('sumo_collector_url')



url = "https://login.microsoftonline.com/%s/oauth2/token" % (tenantId)

resourceAppIdUri = 'https://api.securitycenter.microsoft.com'

body = {
    'resource' : resourceAppIdUri,
    'client_id' : appId,
    'client_secret' : appSecret,
    'grant_type' : 'client_credentials'
}


# define function app and its scehdule
app = func.FunctionApp()

@app.function_name(name="mytimer")
@app.schedule(schedule="0 0 22 * * *",
              arg_name="mytimer",
              run_on_startup=False)
def test_function(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.utcnow().replace(
        tzinfo=datetime.timezone.utc).isoformat()
    if mytimer.past_due:
        logging.info('The timer is past due!')
    logging.info('Python timer trigger function ran at %s', utc_timestamp)
    filename = defenderReport()
    print("file name is:", filename)
    sendEmail(filename)


def defenderReport():

    # Authenticate to Azure uisng aap client and secret and get token
    data = urllib.parse.urlencode(body).encode("utf-8")

    req = urllib.request.Request(url, data)
    response = urllib.request.urlopen(req)
    jsonResponse = json.loads(response.read())
    aadToken = jsonResponse["access_token"]

    # run query using the token
    queryFile = open("query.txt", 'r')
    query = queryFile.read()
    queryFile.close()
    # print(query)


    secUrl = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
    headers = {
        'Content-Type' : 'application/json',
        'Accept' : 'application/json',
        'Authorization' : "Bearer " + aadToken
    }

    data = json.dumps({ 'Query' : query }).encode("utf-8")
    # print(data)
    req = urllib.request.Request(secUrl, data, headers)
    response = urllib.request.urlopen(req)
    # print("getting data from Defender portal, can take appox 5 sec....")
    # time.sleep(5)
    jsonResponse = json.loads(response.read())
    schema = jsonResponse["Schema"]
    results = jsonResponse["Results"]
    # print(results)

    # export output from query to a text file containing json array
    """
    home_directory = os.path.expanduser("~")
    downloads_folder = os.path.join(home_directory, "Downloads")
    if not os.path.exists(downloads_folder):
        os.makedirs(downloads_folder)

    """

    current_date = time.strftime("%Y%m%d")
    directory_path = "/tmp/"
    file_path_txt = f"{directory_path}defender_log_{current_date}.txt"
    file_path_csv = f"{directory_path}defender_log_{current_date}.csv"
    # filenametxt = f"defender_log_{current_date}.txt"
    # filenamecsv = f"defender_log_{current_date}.csv"
    # file_path_txt = os.path.join(downloads_folder, filenametxt)
    # file_path_csv = os.path.join(downloads_folder, filenamecsv)


    # write to csv file
    print("writing output to csv file......")
    outputFile = open(file_path_csv, 'w')
    output = csv.writer(outputFile)
    output.writerow(results[0].keys())
    for result in results:
        output.writerow(result.values())
    outputFile.close()


    # write output to text file
    print("writing output to txt file......")
    with open(file_path_txt, "w", encoding="utf-8") as output_file:
        for result in results:
            result_json = json.dumps(result, ensure_ascii=False)
            output_file.write(result_json + "\n")
    output_file.close()
    # time.sleep(1)

    """
    # upload logs to Sumologic
    print("uploading data to sumologic......")
    cmd = 'curl -v -X POST -H "X-Sumo-Category:security/defender/hunting" -H "X-Sumo-Name:%s" -T %s %s --ssl-no-revoke' %(file_path_txt, file_path_txt, sumourl)
    # print(cmd)
    returned_value = os.system(cmd)
    # print('returned value:', returned_value)
    print("Done.... Check Somologic portal for uploaded data.")
    """

    return file_path_csv


def sendEmail(attachment):

    connection_string = os.environ.get('comm_service_conn_string')

    with open(attachment, "rb") as file:
        file_bytes_b64 = base64.b64encode(file.read())

    message = {
        "content": {
            "subject": "Defender Vulnerability Report",
            "plainText": "Copy the content of the attached CSV file into the excel file in Teams channel: IT Infrastructure and Operations Team > Files > Security Reporting > Defender > Defender-critical-high-with-exploit.xlsx > 'Defender-critical-high-with-exp' Tab. After copying go to 'summary' tab > click anywhere inside table > PivotTable > Refress All data"

        },
        "recipients": {
            "to": [
                {
                    "address": "ash.dey@standards.org.au",
                    "displayName": "Ash Dey"
                }
            ]
        },
        "senderAddress": "DoNotReply@9a80dbdd-e3ba-4c7d-9ffb-9a5e953179a6.azurecomm.net",
        "replyTo": [
            {
                "address": "ash.dey@standards.org.au",  # Email address. Required.
                "displayName": "Ash Dey"  # Optional. Email display name.
            }
        ],
        "attachments": [
            {
                "name": "defender-report",
                "contentType": "text/csv",
                "contentInBase64": file_bytes_b64.decode()
            }
        ]
    }


    POLLER_WAIT_TIME = 10

    try:
        # endpoint = "https://central-communication-service.australia.communication.azure.com"
        # email_client = EmailClient(endpoint, DefaultAzureCredential())
        print("set email client...")
        email_client = EmailClient.from_connection_string(connection_string)

        print("send email....")
        poller = email_client.begin_send(message);

        time_elapsed = 0
        while not poller.done():
            print("Email send poller status: " + poller.status())

            poller.wait(POLLER_WAIT_TIME)
            time_elapsed += POLLER_WAIT_TIME

            if time_elapsed > 18 * POLLER_WAIT_TIME:
                raise RuntimeError("Polling timed out.")

        if poller.result()["status"] == "Succeeded":
            print(f"Successfully sent the email (operation id: {poller.result()['id']})")
        else:
            raise RuntimeError(str(poller.result()["error"]))

    except Exception as ex:
        print(ex)
