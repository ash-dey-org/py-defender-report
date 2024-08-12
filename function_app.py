# Extract report from Defender API
# upload to Sumologic
# download file from sharepoint
# update excel
# upload updated to sharepoint
# send email

# pip install azure-identity
# pip install azure-communication-identity
# pip install azure-communication-email
# pip install azure-keyvault-secrets
# pip install azure-keyvault-certificates
# pip install office365-REST-Python-Client
# pip install openpyxl
# pip install azure-functions

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

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.keyvault.certificates import CertificateClient

from office365.sharepoint.client_context import ClientContext

from openpyxl import load_workbook

# define environment variables and other fixed parameters
tenantId = os.environ.get('azure_tenant_id')
appId = os.environ.get('defender_app_id')
appSecret = os.environ.get('defender_app_secret')
sumoUrl = os.environ.get('sumo_collector_url')
kvUrl = os.environ.get('kv_url')
certName = os.environ.get('cert_name')
sharepointUrl = os.environ.get('sharepoint_url')
sharepointDir = os.environ.get('sharepoint_dir')
sharepointFilePath = os.environ.get('sharepoint_file_path')

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

@app.function_name(name="updateSharepoint")
@app.schedule(schedule="0 0 */3 * * *",
# @app.schedule(schedule="0 */10 * * * *",
              arg_name="updateSharepoint",
              run_on_startup=False)
def test_function1(updateSharepoint: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if updateSharepoint.past_due:
        logging.info('The timer is past due!')
    logging.info('Python timer trigger function ran at %s', utc_timestamp)
    result = defenderReport()
    # uploadDataToSumologic(result[0],sumoUrl)
    print("txt file name is:", result[0])
    print("csv file name is:", result[1])
    ctx = authneticateToSharepoint(kvUrl, certName, sharepointUrl)
    fileDownload = downloadFile(ctx, sharepointFilePath)
    updateExcel(fileDownload, result[1])
    uploadFile (ctx, fileDownload, sharepointDir)
    sendEmail(result[1])

@app.function_name(name="updateSumologic")
@app.schedule(schedule="0 15 22 * * *",
# @app.schedule(schedule="0 */10 * * * *",
              arg_name="updateSumologic",
              run_on_startup=False)
def test_function2(updateSumologic: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if updateSumologic.past_due:
        logging.info('The timer is past due!')
    logging.info('Python timer trigger function ran at %s', utc_timestamp)
    result = defenderReport()
    uploadDataToSumologic(result[0],sumoUrl)
    print("txt file name is:", result[0])
    print("csv file name is:", result[1])
    # ctx = authneticateToSharepoint(kvUrl, certName, sharepointUrl)
    # fileDownload = downloadFile(ctx, sharepointFilePath)
    # updateExcel(fileDownload, result[1])
    # uploadFile (ctx, fileDownload, sharepointDir)
    sendEmail(result[1])

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

    return file_path_txt, file_path_csv

def uploadDataToSumologic(file_path_txt:str,sumourl:str):
    # upload logs to Sumologic
    print("uploading data to sumologic......")
    cmd = 'curl -v -X POST -H "X-Sumo-Category:security/defender/hunting" -H "X-Sumo-Name:%s" -T %s %s --ssl-no-revoke' %(file_path_txt, file_path_txt, sumourl)
    # print(cmd)
    returned_value = os.system(cmd)
    # print('returned value:', returned_value)
    print("Done.... Check Somologic portal for uploaded data.")

def authneticateToSharepoint(kv_url:str, cert_name:str, sharepoint_url:str):

    # Securely retrieve secrets from Azure Key Vault
    credential = DefaultAzureCredential()
    certificate_client = CertificateClient(vault_url=kv_url, credential=credential)
    certificate = certificate_client.get_certificate(certificate_name=cert_name)
    client = SecretClient(vault_url=kv_url, credential=credential)

    # download pem file from key vault
    with open("temp.pem", "w") as pem_file:
        pem_file.write(client.get_secret(cert_name).value)

    client_id = appId   # client.get_secret("defender-app-id").value
    tenant_id = tenantId  # client.get_secret("azure-tenant-id").value
    cert_thumbprint = certificate.properties.x509_thumbprint.hex()

    cert_credentials = {
        "tenant": tenant_id,
        "client_id": client_id,
        "thumbprint": cert_thumbprint,
        "cert_path": "{0}/temp.pem".format(os.path.dirname(__file__)),
    }

    ctx = ClientContext(sharepoint_url).with_client_certificate(**cert_credentials)

    os.remove("temp.pem")
    return ctx

def downloadFile(ctx, sharepoint_file_path:str):
    download_path = os.path.join(os.getcwd(), os.path.basename(sharepoint_file_path))
    with open(download_path, "wb") as local_file:
        file = (
            ctx.web.get_file_by_server_relative_url(sharepoint_file_path)
            .download(local_file)
            .execute_query()
        )
    print("[Ok] file has been downloaded into: {0}".format(download_path))
    return download_path

def updateExcel(src_file:str, csv_file:str):
    # load workbook
    wb1 = load_workbook(src_file)

    # delete exisitng worksheet
    wb1.remove(wb1['Defender-critical-high-with-exp'])

    # create new worksheet at the end
    wb1.create_sheet("Defender-critical-high-with-exp")

    #load worksheet
    ws1 = wb1["Defender-critical-high-with-exp"]

     # open the csv file

    with open(csv_file) as f:
        reader = csv.reader(f, delimiter=',')

        for row in reader:
            ws1.append(row)

    # save worksheet
    wb1.save(src_file)
    print("Excel sheet ", src_file, "updated with new data")

def uploadFile(ctx,filename:str, sharepoint_dir:str):
    web = ctx.web.get_folder_by_server_relative_url(sharepoint_dir)

    with open(filename, "rb") as content_file:
        file_content = content_file.read()
    file = web.upload_file(os.path.basename(filename), file_content).execute_query()
    print("File has been uploaded into: {0}".format(file.serverRelativeUrl))

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
        "senderAddress": "DoNotReply@d737b976-8c58-45e0-a0e7-4c16f5c097c4.azurecomm.net",
        "replyTo": [
            {
                "address": "ash.dey@standards.org.au",  # Email address. Required.
                "displayName": "Ash Dey"  # Optional. Email display name.
            }
        ],
        "attachments": [
            {
                "name": "defender-report.csv",
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

'''
# this part goes inside test function at the top
# used for local testing, comment this section after testing
# uncomment top section and # import azure.functions as func - before pushing code into azure function app
result = defenderReport()
uploadDataToSumologic(result[0],sumoUrl)
print("txt file name is:", result[0])
print("csv file name is:", result[1])
ctx = authneticateToSharepoint(kvUrl, certName, sharepointUrl)
fileDownload = downloadFile(ctx, sharepointFilePath)
updateExcel(fileDownload, result[1])
uploadFile (ctx, fileDownload, sharepointDir)
sendEmail(result[1])

'''