import asyncio

from database.connection import engine, Base

from database import models


async def init():

    async with engine.begin() as conn:

        await conn.run_sync(
            Base.metadata.create_all
        )


if __name__ == "__main__":

    asyncio.run(init())