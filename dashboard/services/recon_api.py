import requests


API_URL = (
    "http://localhost:8000"
)


def discover_subnet(

    target,
    ports,
):

    response = requests.get(

        f"{API_URL}/api/v1/recon/discover",

        params={

            "target": target,

            "ports": ports,
        }
    )

    return response.json()