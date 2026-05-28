import requests


API_URL = (
    "http://localhost:8000"
)


def launch_attack(

    target,
    module_name,
):

    payload = {

        "name": (
            f"{module_name}-simulation"
        ),

        "target": target,

        "modules": [

            module_name
        ],

        "parallel": False,

        "options": {}
    }

    response = requests.post(

        f"{API_URL}/api/v1/simulations",

        json=payload
    )

    return response.json()