from pydantic import BaseModel, ConfigDict
from typing import Optional, List

class TaskBase(BaseModel):
    title: str
    description: Optional[str] = None
    status: str = "todo"

class TaskCreate(TaskBase):
    pass

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None

class Task(TaskBase):
    id: int
    owner_id: int

    model_config = ConfigDict(from_attributes=True)

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    tasks: List[Task] = []

    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    token_type: str