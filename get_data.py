import requests
import hashlib
import pandas as pd
import os
from google.cloud import bigquery, secretmanager


# Access to secret manager
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "secrets.json"

def load(df,project,dataset,table):
    bq = bigquery.Client()

    table_id = f'{project}.{dataset}.{table}'

    job_config = bigquery.LoadJobConfig()
    job_config.write_disposition = bigquery.WriteDisposition.WRITE_APPEND

    try:
        # Load data to BQ
        job = bq.load_table_from_dataframe(df, table_id, job_config=job_config)
        response = job.result()
        print(f"Sucesso! {df.shape[0]} rows appended!")
        return True

    except Exception as e:
        print(f"Erro: {e}.")
        return False
    
def to_string(self,x):
    if x == 'nan':
        return None
    elif x == 'NaN':
        return None
    else:
        return x
    
def access_secret_version(project_id, secret_id, version_id):
    """
    Access the payload for the given secret version if one exists. The version
    can be a version number as a string (e.g. "5") or an alias (e.g. "latest").
    """

    # Import the Secret Manager client library.
    from google.cloud import secretmanager
    import google_crc32c
    # Create the Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()

    # Build the resource name of the secret version.
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"

    # Access the secret version.
    response = client.access_secret_version(request={"name": name})

    # Verify payload checksum.
    crc32c = google_crc32c.Checksum()
    crc32c.update(response.payload.data)
    if response.payload.data_crc32c != int(crc32c.hexdigest(), 16):
        print("Data corruption detected.")
        return response

    # Print the secret payload.
    #
    # WARNING: Do not print the secret in a production environment - this
    # snippet is showing how to access the secret material.
    payload = response.payload.data.decode("UTF-8")
    return payload
    #print("Plaintext: {}".format(payload))
    
    
private = access_secret_version('test67488', 'marvel-key', 'latest')
public = access_secret_version('test67488', 'marvel-public', 'latest')

str2hash = f"1{private}{public}"
result = hashlib.md5(str2hash.encode())

# Access to BQ
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] ="access-bq.json"

res = requests.get(f"http://gateway.marvel.com/v1/public/comics?ts=1&apikey={public}&hash={result.hexdigest()}")

df = pd.json_normalize(res.json(),['data',['results']], meta=['copyright','attributionText'],sep="_",errors='ignore')

load(df,'test67488','marve_teste_conjuntodados','comics')

