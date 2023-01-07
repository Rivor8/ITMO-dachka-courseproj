import sqlalchemy
from sqlalchemy import orm

from .db_session import SqlAlchemyBase


class Station(SqlAlchemyBase):
    __tablename__ = 'stations'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    name = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    code = sqlalchemy.Column(sqlalchemy.String, nullable=True)

    announcements = orm.relation("Announcement", back_populates='station')