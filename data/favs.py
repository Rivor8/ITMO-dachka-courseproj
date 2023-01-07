import sqlalchemy
from sqlalchemy import orm

from .db_session import SqlAlchemyBase


class Fav(SqlAlchemyBase):
    __tablename__ = 'favs'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    station_from = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    station_to = sqlalchemy.Column(sqlalchemy.String, nullable=True)

    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id"))

    user = orm.relation('User')