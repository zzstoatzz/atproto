##################################################################
# THIS IS THE AUTO-GENERATED CODE. DON'T EDIT IT BY HANDS!
# Copyright (C) 2023 Ilya (Marshal) <https://github.com/MarshalX>.
# This file is part of Python atproto SDK. Licenced under MIT.
##################################################################


import typing_extensions as te
from pydantic import Field

from atproto_client.models import base


class Data(base.DataModelBase):
    """Input data model for :obj:`com.atproto.temp.requestPhoneVerification`."""

    phone_number: str = Field(alias='phoneNumber')  #: Phone number.


class DataDict(te.TypedDict):
    phone_number: str  #: Phone number.