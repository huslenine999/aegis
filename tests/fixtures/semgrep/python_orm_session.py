import uuid

from fastapi import FastAPI

from deps import CurrentUser, Item, SessionDep

api = FastAPI()


# Mirrors full-stack-fastapi-template: the session is a SQLModel session, not an HTTP client.
@api.delete("/items/{id}")
def delete_item(session: SessionDep, current_user: CurrentUser, id: uuid.UUID):
    item = session.get(Item, id)
    # ok: python-tainted-request
    session.delete(item)
    session.commit()
