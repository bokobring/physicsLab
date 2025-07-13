# -*- coding: utf-8 -*-

import os
import json
import uuid
import urllib.request
import urllib.error

from physicsLab import plAR
from physicsLab import enums
from physicsLab import errors
from physicsLab.web import _request
from physicsLab.enums import Tag, Category
from physicsLab._typing import Optional, List, TypedDict, Callable


class _api_result(TypedDict):
    Token: str
    AuthCode: Optional[str]
    Data: dict


def _check_response(
    response_json: dict, err_callback: Optional[Callable] = None
) -> _api_result:
    errors.assert_true(err_callback is None or callable(err_callback))

    status_code = response_json["Status"]

    if status_code == 200:
        return response_json
    if err_callback is not None:
        err_callback(status_code)
    raise errors.ResponseFail(
        status_code,
        response_json['Message']
    )


def get_start_page() -> _api_result:
    response_bytes = _request.get_https("physics-api-cn.turtlesim.com", "Users")
    response_json = json.loads(response_bytes)
    return _check_response(response_json)


def get_avatar(
    target_id: str,
    index: int,
    category: str,
    size_category: str,
    usehttps: bool = False,
) -> bytes:
    if not isinstance(target_id, str):
        errors.type_error(
            f"Parameter `target_id` must be of type `str`, but got value `{target_id}` of type `{type(target_id).__name__}`"
        )
    if not isinstance(index, int):
        errors.type_error(
            f"Parameter `index` must be of type `int`, but got value `{index}` of type `{type(index).__name__}`"
        )
    if not isinstance(category, str):
        errors.type_error(
            f"Parameter `category` must be of type `str`, but got value `{category}` of type `{type(category).__name__}`"
        )
    if not isinstance(size_category, str):
        errors.type_error(
            f"Parameter `size_category` must be of type `str`, but got value `{size_category}` of type `{type(size_category).__name__}`"
        )
    if not isinstance(usehttps, bool):
        errors.type_error(
            f"Parameter `usehttps` must be of type `bool`, but got value `{usehttps}` of type `{type(usehttps).__name__}`"
        )
    if category not in ("experiments", "users"):
        raise ValueError(
            f"Parameter `category` must be one of ['experiments', 'users'], but got value `{category} of type '{category}'"
        )
    if size_category not in ("small.round", "thumbnail", "full"):
        raise ValueError(
            f"Parameter `size_category` must be one of ['small.round', 'thumbnail', 'full'], but got value `{size_category} of type '{size_category}'"
        )

    if category == "users":
        category += "/avatars"
    elif category == "experiments":
        category += "/images"
    else:
        errors.unreachable()

    path = (
        f"{category}/{target_id[0:4]}/{target_id[4:6]}/{target_id[6:8]}"
        f"/{target_id[8:]}/{index}.jpg!{size_category}"
    )
    domain = "physics-static-cn.turtlesim.com"

    if usehttps:
        content = _request.get_https(domain, path, verify=False)
    else:
        content = _request.get_http(domain, path)

    if b"<Error>" in content:
        raise IndexError("avatar not found")
    return content


class _User:
    token: str
    auth_code: str
    is_binded: bool
    device_token: str
    user_id: str
    nickname: Optional[str]
    signature: Optional[str]
    gold: int
    level: int
    avatar: int
    avatar_region: int
    decoration: int
    statistic: dict

    def __init__(*args, **kwargs) -> None:
        raise NotImplementedError

    def get_library(self) -> _api_result:
        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Contents/GetLibrary",
            body={
                "Identifier": "Discussions",
                "Language": "Chinese",
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def query_experiments(
        self,
        category: Category,
        tags: Optional[List[Tag]] = None,
        exclude_tags: Optional[List[Tag]] = None,
        languages: Optional[List[str]] = None,
        exclude_languages: Optional[List[str]] = None,
        user_id: Optional[str] = None,
        take: int = 20,
        skip: int = 0,
        from_skip: Optional[str] = None,
    ) -> _api_result:
        if not isinstance(category, Category):
            errors.type_error(
                f"Parameter `category` must be an instance of Category enum, but got value `{category}` of type `{type(category).__name__}`"
            )
        if not isinstance(tags, (list, type(None))):
            errors.type_error(
                f"Parameter `tags` must be of type 'list' or None, but got value `{tags}` of type `{type(tags).__name__}`"
            )
        if tags is not None and not all(isinstance(tag, Tag) for tag in tags):
            errors.type_error(
                f"Parameter `tags` must be a list of Tag enum instances, but got value `{tags} of type list containing non-Tag elements"
            )
        if not isinstance(exclude_tags, (list, type(None))):
            errors.type_error(
                f"Parameter `exclude_tags` must be of type 'list' or None, but got value `{exclude_tags}` of type `{type(exclude_tags).__name__}`"
            )
        if exclude_tags is not None and not all(
            isinstance(tag, Tag) for tag in exclude_tags
        ):
            errors.type_error(
                f"Parameter `exclude_tags` must be a list of Tag enum instances, but got value `{exclude_tags} of type list containing non-Tag elements"
            )
        if not isinstance(languages, (list, type(None))):
            errors.type_error(
                f"Parameter `languages` must be of type `Optional[list]`, but got value `{languages}` of type `{type(languages).__name__}`"
            )
        if languages is not None and not all(
            isinstance(language, str) for language in languages
        ):
            errors.type_error(
                f"Parameter `languages` must be type `list | str`, but got value `{languages}` of type `{type(languages).__name__}`"
            )
        if not isinstance(exclude_languages, (list, type(None))):
            errors.type_error(
                f"Parameter `exclude_languages` must be of type `Optional[list]`, but got value `{exclude_languages}` of type `{type(exclude_languages).__name__}`"
            )
        if exclude_languages is not None and not all(
            isinstance(language, str) for language in exclude_languages
        ):
            errors.type_error(
                f"Parameter `exclude_languages` must be a list of str, but got value `{exclude_languages} of type list containing non-str elements"
            )
        if not isinstance(user_id, (str, type(None))):
            errors.type_error(
                f"Parameter `user_id` must be of type `str` or None, but got value `{user_id}` of type {type(user_id).__name__}`"
            )
        if not isinstance(take, int):
            errors.type_error(
                f"Parameter `take` must be of type `int`, but got value `{take}` of type `{type(take).__name__}`"
            )
        if not isinstance(skip, int):
            errors.type_error(
                f"Parameter `skip` must be of type `int`, but got value `{skip}` of type `{type(skip).__name__}`"
            )
        if not isinstance(from_skip, (str, type(None))):
            errors.type_error(
                f"Parameter `from_skip` must be of type `str` or None, but got value `{from_skip}` of type `{type(from_skip).__name__}`"
            )

        if languages is None:
            languages = []
        if exclude_languages is None:
            exclude_languages = []

        if tags is None:
            _tags = None
        else:
            _tags = [tag.value for tag in tags]

        if exclude_tags is None:
            _exclude_tags = exclude_tags
        else:
            _exclude_tags = [tag.value for tag in exclude_tags]

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Contents/QueryExperiments",
            body={
                "Query": {
                    "Category": category.value,
                    "Languages": languages,
                    "ExcludeLanguages": exclude_languages,
                    "Tags": _tags,
                    "ExcludeTags": _exclude_tags,
                    "ModelTags": None,
                    "ModelID": None,
                    "ParentID": None,
                    "UserID": user_id,
                    "Special": None,
                    "From": from_skip,
                    "Skip": skip,
                    "Take": take,
                    "Days": 0,
                    "Sort": 0,
                    "ShowAnnouncement": False,
                }
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def get_experiment(
        self,
        content_id: str,
        category: Optional[Category] = None,
    ) -> _api_result:
        if not isinstance(content_id, str):
            errors.type_error(
                f"Parameter `content_id` must be of type `str`, but got value `{content_id}` of type `{type(content_id).__name__}`"
            )
        if not isinstance(category, (Category, type(None))):
            errors.type_error(
                f"Parameter `category` must be an instance of Category enum or None, but got value `{category}` of type `{type(category).__name__}`"
            )

        if category is not None:
            content_id = self.get_summary(content_id, category)["Data"]["ContentID"]

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Contents/GetExperiment",
            body={
                "ContentID": content_id,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def confirm_experiment(
        self, summary_id: str, category: Category, image_counter: int
    ) -> _api_result:
        if not isinstance(summary_id, str):
            errors.type_error(
                f"Parameter `summary_id` must be of type `str`, but got value `{summary_id}` of type `{type(summary_id).__name__}`"
            )
        if not isinstance(category, Category):
            errors.type_error(
                f"Parameter `category` must be an instance of Category enum, but got value `{category}` of type `{type(category).__name__}`"
            )
        if not isinstance(image_counter, int):
            errors.type_error(
                f"Parameter `image_counter` must be of type `int`, but got value `{image_counter}` of type `{type(image_counter).__name__}`"
            )

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Contents/ConfirmExperiment",
            body={
                "SummaryID": summary_id,
                "Category": category.value,
                "Image": image_counter,
                "Extension": ".jpg",
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def remove_experiment(
        self, summary_id: str, category: Category, reason: Optional[str] = None
    ) -> _api_result:
        if not isinstance(summary_id, str):
            errors.type_error(
                f"Parameter `summary_id` must be of type `str`, but got value `{summary_id}` of type `{type(summary_id).__name__}`"
            )
        if not isinstance(category, Category):
            errors.type_error(
                f"Parameter `category` must be an instance of Category enum, but got value `{category}` of type `{type(category).__name__}`"
            )
        if not isinstance(reason, (str, type(None))):
            errors.type_error(
                f"Parameter `reason` must be of type `str` or None, but got value `{reason}` of type `{type(reason).__name__}`"
            )

        _plar_ver = plAR.get_plAR_version()
        plar_ver = (
            f"{_plar_ver[0]}{_plar_ver[1]}{_plar_ver[2]}"
            if _plar_ver is not None
            else "2411"
        )

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Contents/RemoveExperiment",
            body={
                "Category": category.value,
                "SummaryID": summary_id,
                "Hiding": True,
                "Reason": reason,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
                "x-API-Version": plar_ver,
            },
        )

        return _check_response(response)

    def post_comment(
        self,
        target_id: str,
        target_type: str,
        content: str,
        reply_id: Optional[str] = None,
        special: Optional[str] = None,
    ) -> _api_result:
        if not isinstance(target_id, str):
            errors.type_error(
                f"Parameter `target_id` must be of type `str`, but got value `{target_id}` of type `{type(target_id).__name__}`"
            )
        if not isinstance(content, str):
            errors.type_error(
                f"Parameter `content` must be of type `str`, but got value `{content}` of type `{type(content).__name__}`"
            )
        if not isinstance(target_type, str):
            errors.type_error(
                f"Parameter `target_type` must be of type `str`, but got value `{target_type}` of type `{type(target_type).__name__}`"
            )
        if not isinstance(reply_id, (str, type(None))):
            errors.type_error(
                f"Parameter `reply_id` must be of type `str` or None, but got value `{reply_id}` of type `{type(reply_id).__name__}`"
            )
        if target_type not in ("User", "Discussion", "Experiment"):
            raise ValueError(
                f"Parameter `target_type` must be one of ['User', 'Discussion', 'Experiment'], but got value `{target_type}`"
            )
        if special not in (None, "Reminder"):
            raise ValueError(
                f"Parameter `special` must be one of [None, 'Reminder'], but got value `{special}`"
            )

        if reply_id is None:
            reply_id = ""

            if (
                content.startswith("回复@")
                or content.startswith("Reply@")
                or content.startswith("Répondre@")
                or content.startswith("Antworten@")
                or content.startswith("Respuesta@")
                or content.startswith("応答@")
                or content.startswith("Відповісти@")
                or content.startswith("Odpowiadać@")
            ):
                _nickname = ""
                is_match: bool = False
                for chr in content:
                    if chr in (":", " "):
                        break
                    elif is_match:
                        _nickname += chr
                    elif chr == "@":
                        is_match = True
                        continue

                if _nickname != "":
                    try:
                        reply_id = self.get_user(_nickname, enums.GetUserMode.by_name)[
                            "Data"
                        ]["User"]["ID"]
                    except errors.ResponseFail:
                        pass

        assert isinstance(reply_id, str)

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Messages/PostComment",
            body={
                "TargetID": target_id,
                "TargetType": target_type,
                "Language": "Chinese",
                "ReplyID": reply_id,
                "Content": content,
                "Special": special,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def remove_comment(self, comment_id: str, target_type: str) -> _api_result:
        if not isinstance(comment_id, str):
            errors.type_error(
                f"Parameter `comment_id` must be of type `str`, but got value `{comment_id}` of type `{type(comment_id).__name__}`"
            )
        if not isinstance(target_type, str):
            errors.type_error(
                f"Parameter `target_type` must be of type `str`, but got value `{target_type}` of type `{type(target_type).__name__}`"
            )
        if target_type not in ("User", "Discussion", "Experiment"):
            raise ValueError(
                f"Parameter `target_type` must be one of ['User', 'Discussion', 'Experiment'], but got value `{target_type}`"
            )

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Messages/RemoveComment",
            body={
                "TargetType": target_type,
                "CommentID": comment_id,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def get_comments(
        self,
        target_id: str,
        target_type: str,
        take: int = 16,
        skip: int = 0,
        comment_id: Optional[str] = None,
    ) -> _api_result:
        if not isinstance(target_id, str):
            errors.type_error(
                f"Parameter `target_id` must be of type `str`, but got value `{target_id}` of type `{type(target_id).__name__}`"
            )
        if not isinstance(target_type, str):
            errors.type_error(
                f"Parameter `target_type` must be of type `str`, but got value `{target_type}` of type `{type(target_type).__name__}`"
            )
        if not isinstance(take, int):
            errors.type_error(
                f"Parameter `take` must be of type `int`, but got value `{take}` of type `{type(take).__name__}`"
            )
        if not isinstance(skip, int):
            errors.type_error(
                f"Parameter `skip` must be of type `int`, but got value `{skip}` of type `{type(skip).__name__}`"
            )
        if not isinstance(comment_id, (str, type(None))):
            errors.type_error(
                f"Parameter `comment_id` must be of type `str` or None, but got value `{comment_id}` of type `{type(comment_id).__name__}`"
            )
        if target_type not in ("User", "Discussion", "Experiment"):
            raise ValueError(
                f"Parameter `target_type` must be one of ['User', 'Discussion', 'Experiment'], but got value `{target_type} of type '{target_type}'"
            )

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Messages/GetComments",
            body={
                "TargetID": target_id,
                "TargetType": target_type,
                "CommentID": comment_id,
                "Take": take,
                "Skip": skip,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def get_summary(self, content_id: str, category: Category) -> _api_result:
        if not isinstance(content_id, str):
            errors.type_error(
                f"Parameter `content_id` must be of type `str`, but got value `{content_id}` of type `{type(content_id).__name__}`"
            )
        if not isinstance(category, Category):
            errors.type_error(
                f"Parameter `category` must be an instance of Category enum, but got value `{category}` of type `{type(category).__name__}`"
            )

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Contents/GetSummary",
            body={
                "ContentID": content_id,
                "Category": category.value,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        def callback(status_code):
            if status_code == 403:
                raise PermissionError("login failed")
            if status_code == 404:
                raise errors.ResponseFail(
                    404,
                    "experiment not found(may be you select category wrong)"
                )

        return _check_response(response, callback)

    def get_derivatives(self, content_id: str, category: Category) -> _api_result:
        if not isinstance(content_id, str):
            errors.type_error(
                f"Parameter `content_id` must be of type `str`, but got value `{content_id}` of type `{type(content_id).__name__}`"
            )
        if not isinstance(category, Category):
            errors.type_error(
                f"Parameter `category` must be an instance of Category enum, but got value `{category}` of type `{type(category).__name__}`"
            )

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Contents/GetDerivatives",
            body={
                "ContentID": content_id,
                "Category": category.value,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def get_user(
        self,
        msg: str,
        get_user_mode: enums.GetUserMode,
    ) -> _api_result:
        if not isinstance(msg, str):
            errors.type_error(
                f"Parameter `msg` must be of type `str`, but got value `{msg}` of type {type(msg).__name__}`"
            )
        if not isinstance(get_user_mode, enums.GetUserMode):
            errors.type_error(
                f"Parameter `get_user_mode` must be an instance of type "
                f"`physicsLab.enums.GetUserMode`, but got value `{get_user_mode}` of type {type(get_user_mode).__name__}`"
            )

        if get_user_mode == enums.GetUserMode.by_id:
            body = {"ID": msg}
        elif get_user_mode == enums.GetUserMode.by_name:
            body = {"Name": msg}
        else:
            errors.unreachable()

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Users/GetUser",
            body=body,
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def get_profile(self, user_id: Optional[str] = None) -> _api_result:
        if not isinstance(user_id, (str, type(None))):
            errors.type_error(f"Parameter user_id must be of type `Optional[str]`, but got value {user_id} of type `{type(user_id).__name__}`")

        if user_id is None:
            user_id = self.user_id
        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Contents/GetProfile",
            body={
                "ID": user_id,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def star_content(
        self, content_id: str, category: Category, star_type: int, status: bool = True
    ) -> _api_result:
        if not isinstance(content_id, str):
            errors.type_error(
                f"Parameter `content_id` must be of type `str`, but got value `{content_id}` of type `{type(content_id).__name__}`"
            )
        if not isinstance(category, Category):
            errors.type_error(
                f"Parameter `category` must be an instance of Category enum, but got value `{category}` of type `{type(category).__name__}`"
            )
        if not isinstance(status, bool):
            errors.type_error(
                f"Parameter `status` must be of type `bool`, but got value `{status}` of type `{type(status).__name__}`"
            )
        if not isinstance(star_type, int):
            errors.type_error(
                f"Parameter `star_type` must be of type `int`, but got value `{star_type}` of type `{type(star_type).__name__}`"
            )
        if star_type not in (0, 1):
            raise ValueError(
                f"Parameter `star_type` must be one of [0, 1], but got value `{star_type} of type '{star_type}'"
            )

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Contents/StarContent",
            body={
                "ContentID": content_id,
                "Status": status,
                "Category": category.value,
                "Type": star_type,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def upload_image(
        self, policy: str, authorization: str, image_path: str
    ) -> _api_result:
        if policy is None or authorization is None:
            raise RuntimeError("Sorry, Physics-Lab-AR can't upload this iamge")
        if not isinstance(policy, str):
            errors.type_error(
                f"Parameter `policy` must be of type `str`, but got value `{policy}` of type `{type(policy).__name__}`"
            )
        if not isinstance(authorization, str):
            errors.type_error(
                f"Parameter `authorization` must be of type `str`, but got value `{authorization}` of type `{type(authorization).__name__}`"
            )
        if not isinstance(image_path, str):
            errors.type_error(
                f"Parameter `image_path` must be of type `str`, but got value `{image_path}` of type `{type(image_path).__name__}`"
            )
        if not os.path.exists(image_path) or not os.path.isfile(image_path):
            raise FileNotFoundError(f"`{image_path}` not found")

        with open(image_path, "rb") as f:
            image_content = f.read()

        boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
        
        body = b""
        body += f'--{boundary}\r\n'.encode('utf-8')
        body += b'Content-Disposition: form-data; name="policy"\r\n\r\n'
        body += policy.encode('utf-8') + b'\r\n'
        
        body += f'--{boundary}\r\n'.encode('utf-8')
        body += b'Content-Disposition: form-data; name="authorization"\r\n\r\n'
        body += authorization.encode('utf-8') + b'\r\n'

        body += f'--{boundary}\r\n'.encode('utf-8')
        body += b'Content-Disposition: form-data; name="file"; filename="temp.jpg"\r\n'
        body += b'Content-Type: image/jpeg\r\n\r\n'
        body += image_content + b'\r\n'
        
        body += f'--{boundary}--\r\n'.encode('utf-8')
        
        headers = {'Content-Type': f'multipart/form-data; boundary={boundary}'}
        
        req = urllib.request.Request("http://v0.api.upyun.com/qphysics", data=body, headers=headers, method='POST')

        try:
            with urllib.request.urlopen(req) as response:
                if response.status >= 400:
                    raise errors.ResponseFail(response.status, response.reason)
                response_data = json.loads(response.read())
                if response_data.get("code") != 200:
                    raise errors.ResponseFail(response_data.get("code"), response_data.get('message'))
                return response_data
        except urllib.error.HTTPError as e:
            raise errors.ResponseFail(e.code, e.reason) from e


    def get_message(self, message_id: str) -> _api_result:
        if not isinstance(message_id, str):
            errors.type_error(
                f"Parameter `message_id` must be of type `str`, but got value `{message_id}` of type `{type(message_id).__name__}`"
            )

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Messages/GetMessage",
            body={
                "MessageID": message_id,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def get_messages(
        self,
        category_id: int,
        skip: int = 0,
        take: int = 16,
        no_templates: bool = True,
    ) -> _api_result:
        if category_id not in (0, 1, 2, 3, 4, 5):
            errors.type_error(
                f"Parameter `category_id` must be an integer within [0, 5], but got value `{category_id}` of type `{category_id}`"
            )
        if not isinstance(skip, int):
            errors.type_error(
                f"Parameter `skip` must be of type `int`, but got value `{skip}` of type `{type(skip).__name__}`"
            )
        if not isinstance(take, int):
            errors.type_error(
                f"Parameter `take` must be of type `int`, but got value `{take}` of type `{type(take).__name__}`"
            )
        if not isinstance(no_templates, bool):
            errors.type_error(
                f"Parameter `no_templates` must be of type `bool`, but got value `{no_templates}` of type `{type(no_templates).__name__}`"
            )

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Messages/GetMessages",
            body={
                "CategoryID": category_id,
                "Skip": skip,
                "Take": take,
                "NoTemplates": no_templates,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def get_supporters(
        self,
        content_id: str,
        category: Category,
        skip: int = 0,
        take: int = 16,
    ) -> _api_result:
        if not isinstance(content_id, str):
            errors.type_error(
                f"Parameter `content_id` must be of type `str`, but got value `{content_id}` of type `{type(content_id).__name__}`"
            )
        if not isinstance(category, Category):
            errors.type_error(
                f"Parameter `category` must be an instance of Category enum, but got value `{category}` of type `{type(category).__name__}`"
            )
        if not isinstance(skip, int):
            errors.type_error(
                f"Parameter `skip` must be of type `int`, but got value `{skip}` of type `{type(skip).__name__}`"
            )
        if not isinstance(take, int):
            errors.type_error(
                f"Parameter `take` must be of type `int`, but got value `{take}` of type `{type(take).__name__}`"
            )

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Contents/GetSupporters",
            body={
                "ContentID": content_id,
                "Category": category.value,
                "Skip": skip,
                "Take": take,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def get_relations(
        self,
        user_id: str,
        display_type: str = "Follower",
        skip: int = 0,
        take: int = 20,
        query: str = "",
    ) -> _api_result:
        if display_type not in ("Follower", "Following"):
            raise ValueError(
                f"Parameter `display_type` must be one of ['Follower', 'Following'], but got value `{display_type}` of type `{display_type}`"
            )
        if not isinstance(user_id, str):
            errors.type_error(
                f"Parameter `user_id` must be of type `str`, but got value `{user_id}` of type `{type(user_id).__name__}`"
            )
        if not isinstance(skip, int):
            errors.type_error(
                f"Parameter `skip` must be of type `int`, but got value `{skip}` of type `{type(skip).__name__}`"
            )
        if not isinstance(take, int):
            errors.type_error(
                f"Parameter `take` must be of type `int`, but got value `{take}` of type `{type(take).__name__}`"
            )

        if display_type == "Follower":
            display_type_ = 0
        elif display_type == "Following":
            display_type_ = 1
        else:
            errors.unreachable()

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Users/GetRelations",
            body={
                "UserID": user_id,
                "DisplayType": display_type_,
                "Skip": skip,
                "Take": take,
                "Query": query,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def follow(self, target_id: str, action: bool = True) -> _api_result:
        if not isinstance(target_id, str):
            errors.type_error(
                f"Parameter `target_id` must be of type `str`, but got value `{target_id}` of type `{type(target_id).__name__}`"
            )
        if not isinstance(action, bool):
            errors.type_error(
                f"Parameter `action` must be of type `bool`, but got value `{action}` of type `{type(action).__name__}`"
            )

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Users/Follow",
            body={
                "TargetID": target_id,
                "Action": int(action),
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def rename(self, nickname: str) -> _api_result:
        if not isinstance(nickname, str):
            errors.type_error(
                f"Parameter `nickname` must be of type `str`, but got value `{nickname}` of type {type(nickname).__name__}`"
            )

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Users/Rename",
            body={
                "Target": nickname,
                "UserID": self.user_id,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def modify_information(self, target: str) -> _api_result:
        if not isinstance(target, str):
            errors.type_error(
                f"Parameter `target` must be of type `str`, but got value `{target}` of type `{type(target).__name__}`"
            )

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Users/ModifyInformation",
            body={
                "Target": target,
                "Field": "Signature",
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def receive_bonus(self, activity_id: str, index: int) -> _api_result:
        if not isinstance(activity_id, str):
            errors.type_error(
                f"Parameter `activity_id` must be of type `str`, but got value `{activity_id}` of type `{type(activity_id).__name__}`"
            )
        if not isinstance(index, int):
            errors.type_error(
                f"Parameter `index` must be of type `int`, but got value `{index}` of type `{type(index).__name__}`"
            )
        if index < 0:
            raise ValueError(
                f"Parameter `index` must be a non-negative integer, but got value `{index}`"
            )

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Users/ReceiveBonus",
            body={
                "ActivityID": activity_id,
                "Index": index,
                "Statistic": self.statistic,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def ban(self, target_id: str, reason: str, length: int) -> _api_result:
        if not isinstance(target_id, str):
            errors.type_error(
                f"Parameter target_id must be of type `str`, but got value `{target_id}` of type `{type(target_id).__name__}`"
            )
        if not isinstance(reason, str):
            errors.type_error(
                f"Parameter reason must be of type `str`, but got value `{reason}` of type `{type(reason).__name__}`"
            )
        if not isinstance(length, int):
            errors.type_error(
                f"Parameter length must be of type `int`, but got value `{length}` of type `{type(length).__name__}`"
            )

        if length <= 0:
            raise ValueError

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Users/Ban",
            body={
                "TargetID": target_id,
                "Reason": reason,
                "Length": length,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)

    def unban(self, target_id: str, reason: str) -> _api_result:
        if not isinstance(target_id, str):
            errors.type_error(
                f"Parameter target_id must be of type `str`, but got value `{target_id}` of type `{type(target_id).__name__}`"
            )
        if not isinstance(reason, str):
            errors.type_error(
                f"Parameter reason must be of type `str`, but got value `{reason}` of type `{type(reason).__name__}`"
            )

        response = _request.post_https(
            "physics-api-cn.turtlesim.com",
            "Users/Unban",
            body={
                "TargetID": target_id,
                "Reason": reason,
            },
            header={
                "Content-Type": "application/json",
                "x-API-Token": self.token,
                "x-API-AuthCode": self.auth_code,
            },
        )

        return _check_response(response)
