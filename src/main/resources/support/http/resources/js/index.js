var editors = [];
var response = $('#response');
var send = $('#send_modifier');
var but_expand = document.querySelectorAll('[data-expanded]');
for (var i = 0; i < but_expand.length; i++) {
    but_expand[i].addEventListener('click', function (event) {
        var tg = event.target;
        if (tg.dataset.expanded === 'true') {
            tg.dataset.expanded = 'false';
        } else if (tg.dataset.expanded === 'false') {
            tg.dataset.expanded = 'true';
        }
    });
}

var translate = {
    "1-1-1": "查看所有API权限",
    "1-1-2": "查看某方法的所有API权限",
    "1-1-3": "查看某API所有方法的权限",
    "1-1-4": "查看具体API的权限",

    "1-2-1": "添加完整的权限",
    "1-2-2": "添加【需要】的角色（require role）",
    "1-2-3": "添加【排除】的角色（exclude role）",
    "1-2-4": "添加【需要】的权限（require permission）",
    "1-2-5": "添加【排除】的权限（exclude permission）",

    "1-3-1": "修改【需要】的角色（require role）",
    "1-3-2": "修改【排除】的角色（exclude role）",
    "1-3-3": "修改【需要】的权限（require permission）",
    "1-3-4": "修改【排除】的权限（exclude permission）",

    "1-4-1": "删除API的权限",

    "2-1-1": "查看某个API所有的参数权限",
    "2-1-2": "查看某个API某个参数的权限",

    "2-2-1": "添加PATH参数的【ROLE】权限 - range",
    "2-2-2": "添加PATH参数的【ROLE】权限 - resources",
    "2-2-3": "添加Request Param参数的【ROLE】权限 - range",
    "2-2-4": "添加Request Param参数的【ROLE】权限 - resources",
    "2-2-5": "添加PATH参数的【PERMISSION】权限 - range",
    "2-2-6": "添加PATH参数的【PERMISSION】权限 - resources",
    "2-2-7": "添加Request Param参数的【PERMISSION】权限 - range",
    "2-2-8": "添加Request Param参数的【PERMISSION】权限 - resources",

    "2-3-1": "修改PATH参数的指定索引下标的【ROLE】权限 - range",
    "2-3-2": "修改PATH参数的指定索引下标的【ROLE】权限 - resources",
    "2-3-3": "修改Request Param参数的指定索引下标的【ROLE】权限 - range",
    "2-3-4": "修改Request Param参数的指定索引下标的【ROLE】权限 - resources",
    "2-3-5": "修改PATH参数的指定索引下标的【PERMISSION】权限 - range",
    "2-3-6": "修改PATH参数的指定索引下标的【PERMISSION】权限 - resources",
    "2-3-7": "修改Request Param参数的指定索引下标的【PERMISSION】权限 - range",
    "2-3-8": "修改Request Param参数的指定索引下标的【PERMISSION】权限 - resources",

    "2-4-1": "删除参数的PATH权限",
    "2-4-2": "删除参数的Request Param权限",
    "2-4-3": "删除参数的PATH的指定索引下标的权限",
    "2-4-4": "删除参数的Request Param的指定索引下标的权限",

    "3-1-1": "查看所有类的数据行权限信息",
    "3-1-2": "查看某个类的数据行权限信息",
    "3-1-3": "查看某个类的上的指定索引的数据行信息",

    "3-2-1": "添加（require role）数据行权限信息",
    "3-2-2": "添加（exclude role）数据行权限信息",
    "3-2-3": "添加（require permission）数据行权限信息",
    "3-2-4": "添加（exclude permission）数据行权限信息",

    "3-3-1": "修改数据行权限的Rule规则信息",
    "3-3-2": "修改数据行权限的权限规则信息",
    "3-3-3": "修改数据行权限的参数规则信息",

    "3-4-1": "删除数据行的",
    "3-4-2": "删除类上面的指定索引下标的数据行权限信息",

    "4-1-1": "查看所有类的所有数据列权限",
    "4-1-2": "查看某个类的所有数据列权限",

    "4-2-1": "添加数据列权限",

    "4-3-1": "修改数据列权限",

    "4-4-1": "删除某个类的某个字段的数据列权限",
    "4-4-2": "删除某个类的所有数据列权限",


    "5-1-1": "查看某个RateLimit",

    "5-2-1": "添加&覆盖RateLimit",

    "5-3-1": "删除RateLimit"
}

var template = {
    "查看所有API权限": {
        "operate": "READ",
        "target": "API",
    },
    "查看某方法的所有API权限": {
        "operate": "READ",
        "target": "API",
        "method": "",
    },
    "查看某API所有方法的权限": {
        "operate": "READ",
        "target": "API",
        "api": ""
    },
    "查看具体API的权限": {
        "operate": "READ",
        "target": "API",
        "method": "",
        "api": ""
    },

    "添加完整的权限": {
        "operate": "ADD",
        "target": "API",
        "method": "",
        "api": "",
        "role": {
            "require": [""],
            "exclude": [""]
        },
        "permission": {
            "require": [""],
            "exclude": [""]
        }
    },
    "添加【需要】的角色（require role）": {
        "operate": "ADD",
        "target": "API",
        "method": "",
        "api": "",
        "role": {
            "require": [""]
        },
    },
    "添加【排除】的角色（exclude role）": {
        "operate": "ADD",
        "target": "API",
        "method": "",
        "api": "",
        "role": {
            "exclude": [""]
        }
    },
    "添加【需要】的权限（require permission）": {
        "operate": "ADD",
        "target": "API",
        "method": "",
        "api": "",
        "permission": {
            "require": [""],
        }
    },
    "添加【排除】的权限（exclude permission）": {
        "operate": "ADD",
        "target": "API",
        "method": "",
        "api": "",
        "permission": {
            "exclude": [""]
        }
    },

    "修改【需要】的角色（require role）": {
        "operate": "MODIFY",
        "target": "API",
        "method": "",
        "api": "",
        "role": {
            "require": [""]
        }
    },
    "修改【排除】的角色（exclude role）": {
        "operate": "MODIFY",
        "target": "API",
        "method": "",
        "api": "",
        "role": {
            "exclude": [""]
        }
    },
    "修改【需要】的权限（require permission）": {
        "operate": "MODIFY",
        "target": "API",
        "method": "",
        "api": "",
        "permission": {
            "require": [""]
        }
    },
    "修改【排除】的权限（exclude permission）": {
        "operate": "MODIFY",
        "target": "API",
        "method": "",
        "api": "",
        "permission": {
            "exclude": [""]
        }
    },

    "删除API的权限": {
        "operate": "DEL",
        "target": "API",
        "method": "",
        "api": ""
    },

    "查看某个API所有的参数权限": {
        "operate": "READ",
        "method": "",
        "api": "",
    },
    "查看某个API某个参数的权限": {
        "operate": "READ",
        "method": "",
        "api": "",
        "value": ""
    },

    "添加PATH参数的【ROLE】权限 - range": {
        "operate": "ADD",
        "target": "PATH_VARIABLE_ROLE",
        "method": "",
        "api": "",
        "paramName": "",
        "role": {
            "require": [""]
        },
        "range": [""]
    },
    "添加PATH参数的【ROLE】权限 - resources": {
        "operate": "ADD",
        "target": "PATH_VARIABLE_ROLE",
        "method": "",
        "api": "",
        "paramName": "",
        "role": {
            "require": [""]
        },
        "resources": [""]
    },
    "添加Request Param参数的【ROLE】权限 - range": {
        "operate": "ADD",
        "target": "REQUEST_PARAM_ROLE",
        "method": "",
        "api": "",
        "paramName": "",
        "role": {
            "require": [""]
        },
        "range": [""]
    },
    "添加Request Param参数的【ROLE】权限 - resources": {
        "operate": "ADD",
        "target": "REQUEST_PARAM_ROLE",
        "method": "",
        "api": "",
        "paramName": "",
        "role": {
            "require": [""]
        },
        "resources": [""]
    },
    "添加PATH参数的【PERMISSION】权限 - range": {
        "operate": "ADD",
        "target": "PATH_VARIABLE_PERMISSION",
        "method": "",
        "api": "",
        "paramName": "",
        "role": {
            "require": [""]
        },
        "range": [""]
    },
    "添加PATH参数的【PERMISSION】权限 - resources": {
        "operate": "ADD",
        "target": "PATH_VARIABLE_PERMISSION",
        "method": "",
        "api": "",
        "paramName": "",
        "role": {
            "require": [""]
        },
        "resources": [""]
    },
    "添加Request Param参数的【PERMISSION】权限 - range": {
        "operate": "ADD",
        "target": "REQUEST_PARAM_PERMISSION",
        "method": "",
        "api": "",
        "paramName": "",
        "role": {
            "require": [""]
        },
        "range": [""]
    },
    "添加Request Param参数的【PERMISSION】权限 - resources": {
        "operate": "ADD",
        "target": "REQUEST_PARAM_PERMISSION",
        "method": "",
        "api": "",
        "paramName": "",
        "role": {
            "require": [""]
        },
        "resources": [""]
    },

    "修改PATH参数的指定索引下标的【ROLE】权限 - range": {
        "operate": "MODIFY",
        "target": "PATH_VARIABLE_ROLE",
        "method": "",
        "api": "",
        "paramName": "",
        "index": 0,
        "role": {
            "require": [""]
        },
        "range": [""]
    },
    "修改PATH参数的指定索引下标的【ROLE】权限 - resources": {
        "operate": "MODIFY",
        "target": "PATH_VARIABLE_ROLE",
        "method": "",
        "api": "",
        "paramName": "",
        "index": 0,
        "role": {
            "require": [""]
        },
        "resources": [""]
    },
    "修改Request Param参数的指定索引下标的【ROLE】权限 - range": {
        "operate": "MODIFY",
        "target": "REQUEST_PARAM_ROLE",
        "method": "",
        "api": "",
        "paramName": "",
        "index": 0,
        "role": {
            "require": [""]
        },
        "range": [""]
    },
    "修改Request Param参数的指定索引下标的【ROLE】权限 - resources": {
        "operate": "MODIFY",
        "target": "REQUEST_PARAM_ROLE",
        "method": "",
        "api": "",
        "paramName": "",
        "index": 0,
        "role": {
            "require": [""]
        },
        "resources": [""]
    },
    "修改PATH参数的指定索引下标的【PERMISSION】权限 - range": {
        "operate": "MODIFY",
        "target": "PATH_VARIABLE_PERMISSION",
        "method": "",
        "api": "",
        "paramName": "",
        "index": 0,
        "role": {
            "require": [""]
        },
        "range": [""]
    },
    "修改PATH参数的指定索引下标的【PERMISSION】权限 - resources": {
        "operate": "MODIFY",
        "target": "PATH_VARIABLE_PERMISSION",
        "method": "",
        "api": "",
        "paramName": "",
        "index": 0,
        "role": {
            "require": [""]
        },
        "resources": [""]
    },
    "修改Request Param参数的指定索引下标的【PERMISSION】权限 - range": {
        "operate": "MODIFY",
        "target": "REQUEST_PARAM_PERMISSION",
        "method": "",
        "api": "",
        "paramName": "",
        "index": 0,
        "role": {
            "require": [""]
        },
        "range": [""]
    },
    "修改Request Param参数的指定索引下标的【PERMISSION】权限 - resources": {
        "operate": "MODIFY",
        "target": "REQUEST_PARAM_PERMISSION",
        "method": "",
        "api": "",
        "paramName": "",
        "index": 0,
        "role": {
            "require": [""]
        },
        "resources": [""]
    },

    "删除参数的PATH权限": {
        "operate": "DEL",
        "target": "PATH",
        "method": "",
        "api": "",
        "paramName": "",
    },
    "删除参数的Request Param权限": {
        "operate": "DEL",
        "target": "PARAM",
        "method": "",
        "api": "",
        "paramName": "",
    },
    "删除参数的PATH的指定索引下标的权限": {
        "operate": "DEL",
        "target": "PATH",
        "method": "",
        "api": "",
        "paramName": "",
        "index": 0
    },
    "删除参数的Request Param的指定索引下标的权限": {
        "operate": "DEL",
        "target": "PARAM",
        "method": "",
        "api": "",
        "paramName": "",
        "index": 0
    },

    "查看所有类的数据行权限信息": {
        "operate": "READ",
        "target": "DATA_ROW"
    },
    "查看某个类的数据行权限信息": {
        "operate": "READ",
        "target": "DATA_ROW",
        "className": ""
    },
    "查看某个类的上的指定索引的数据行信息": {
        "operate": "READ",
        "target": "DATA_ROW",
        "className": "",
        "index": 0
    },

    "添加（require role）数据行权限信息": {
        "operate": "ADD",
        "target": "DATA_ROW",
        "className": "",
        "index": 0,
        "condition": "",
        "argsMap": {},
        "role": {
            "require": [""]
        }
    },
    "添加（exclude role）数据行权限信息": {
        "operate": "ADD",
        "target": "DATA_ROW",
        "className": "",
        "index": 0,
        "condition": "",
        "argsMap": {},
        "role": {
            "exclude": [""]
        }
    },
    "添加（require permission）数据行权限信息": {
        "operate": "ADD",
        "target": "DATA_ROW",
        "className": "",
        "index": 0,
        "condition": "",
        "argsMap": {},
        "permission": {
            "require": [""]
        }
    },
    "添加（exclude permission）数据行权限信息": {
        "operate": "ADD",
        "target": "DATA_ROW",
        "className": "",
        "index": 0,
        "condition": "",
        "argsMap": {},
        "permission": {
            "exclude": [""]
        }
    },

    "修改数据行权限的Rule规则信息": {
        "operate": "MODIFY",
        "target": "DATA_ROW",
        "className": "",
        "index": 0,
        "condition": ""
    },
    "修改数据行权限的权限规则信息": {
        "operate": "MODIFY",
        "target": "DATA_ROW",
        "className": "",
        "index": 0,
        "rule": {
            "require": [""]
        }
    },
    "修改数据行权限的参数规则信息": {
        "operate": "MODIFY",
        "target": "DATA_ROW",
        "className": "",
        "index": 0,
        "argsMap": {}
    },

    "删除类上面的所有数据行权限信息": {
        "operate": "DEL",
        "target": "DATA_ROW",
        "className": ""
    },
    "删除类上面的指定索引下标的数据行权限信息": {
        "operate": "DEL",
        "target": "DATA_ROW",
        "className": "",
        "index": 0
    },

    "查看所有类的所有数据列权限": {
        "operate": "READ",
        "target": "DATA_COL"
    },
    "查看某个类的所有数据列权限": {
        "operate": "READ",
        "target": "DATA_COL",
        "className": ""
    },

    "添加数据列权限": {
        "operate": "ADD",
        "target": "DATA_COL",
        "className": "",
        "fieldName": "",
        "role": {
            "require": [""]
        }
    },

    "修改数据列权限": {
        "operate": "MODIFY",
        "target": "DATA_COL",
        "className": "",
        "fieldName": "",
        "role": {
            "require": [""]
        }
    },

    "删除某个类的某个字段的数据列权限": {
        "operate": "DEL",
        "target": "DATA_COL",
        "className": "",
        "fieldName": "",
    },
    "删除某个类的所有数据列权限": {
        "operate": "DEL",
        "target": "DATA_COL",
        "className": "",
    },


    "查看某个RateLimit": {
        "operate": "READ",
        "target": "RATE",
        "method": "",
        "api": ""
    },
    "添加&覆盖RateLimit": {
        "operate": "ADD",
        "target": "RATE",
        "method": "",
        "api": "",
        "rateLimit": {
            "window": "",
            "maxRequests": 0,
            "punishmentTime": [""],
            "minInterval": "",
            "associatedPatterns": [""],
            "bannedType": "API"
        }
    },
    "删除RateLimit": {
        "operate": "DEL",
        "target": "RATE",
        "method": "",
        "api": ""
    }
}

var json_jstree = {
    "plugins": [
        "wholerow"
    ],
    "checkbox": {},
    "core": {
        "multiple": false,
        "themes": {
            "variant": "large"
        },
        "data": [{
            "text": "Authz操作模版",
            "icon": "img/logo.png",
            "state": {
                "opened": true,
                "selected": false
            },
            "children": [
                {
                    "text": "API",
                    "icon": "img/tree.png",
                    "state": {
                        "opened": true,
                        "selected": false
                    },
                    "children": [
                        {
                            "text": "查看",
                            "icon": "img/get.png",
                            "id": "1-1",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [{
                                "text": translate["1-1-1"],
                                "icon": "img/get.png",
                                "id": "1-1-1",
                            }, {
                                "text": translate["1-1-2"],
                                "icon": "img/get.png",
                                "id": "1-1-2",
                            }, {
                                "text": translate["1-1-3"],
                                "icon": "img/get.png",
                                "id": "1-1-3",
                            }, {
                                "text": translate["1-1-4"],
                                "icon": "img/get.png",
                                "id": "1-1-4",
                            }]
                        },
                        {
                            "text": "添加",
                            "icon": "img/add.png",
                            "id": "1-2",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [{
                                "text": translate["1-2-1"],
                                "icon": "img/add.png",
                                "id": "1-2-1",
                            }, {
                                "text": translate["1-2-2"],
                                "icon": "img/add.png",
                                "id": "1-2-2",
                            }, {
                                "text": translate["1-2-3"],
                                "icon": "img/add.png",
                                "id": "1-2-3",
                            }, {
                                "text": translate["1-2-4"],
                                "icon": "img/add.png",
                                "id": "1-2-4",
                            }, {
                                "text": translate["1-2-5"],
                                "icon": "img/add.png",
                                "id": "1-2-5",
                            }]
                        },
                        {
                            "text": "修改",
                            "icon": "img/update.png",
                            "id": "1-3",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [{
                                "text": translate["1-3-1"],
                                "icon": "img/update.png",
                                "id": "1-3-1",
                            }, {
                                "text": translate["1-3-2"],
                                "icon": "img/update.png",
                                "id": "1-3-2",
                            }, {
                                "text": translate["1-3-3"],
                                "icon": "img/update.png",
                                "id": "1-3-3",
                            }, {
                                "text": translate["1-3-4"],
                                "icon": "img/update.png",
                                "id": "1-3-4",
                            }]
                        },
                        {
                            "text": "删除",
                            "icon": "img/delete.png",
                            "id": "1-4",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [{
                                "text": translate["1-4-1"],
                                "icon": "img/delete.png",
                                "id": "1-4-1",
                            }]
                        }
                    ]
                },
                {
                    "text": "API参数",
                    "icon": "img/tree.png",
                    "state": {
                        "opened": true,
                        "selected": false
                    },
                    "children": [
                        {
                            "text": "查看",
                            "icon": "img/get.png",
                            "id": "2-1",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [{
                                "text": translate["2-1-1"],
                                "icon": "img/get.png",
                                "id": "2-1-1",
                            }, {
                                "text": translate["2-1-2"],
                                "icon": "img/get.png",
                                "id": "2-1-2",
                            }]
                        },
                        {
                            "text": "添加",
                            "icon": "img/add.png",
                            "id": "2-2",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [{
                                "text": translate["2-2-1"],
                                "icon": "img/add.png",
                                "id": "2-2-1",
                            }, {
                                "text": translate["2-2-2"],
                                "icon": "img/add.png",
                                "id": "2-2-2",
                            }, {
                                "text": translate["2-2-3"],
                                "icon": "img/add.png",
                                "id": "2-2-3",
                            }, {
                                "text": translate["2-2-4"],
                                "icon": "img/add.png",
                                "id": "2-2-4",
                            }, {
                                "text": translate["2-2-5"],
                                "icon": "img/add.png",
                                "id": "2-2-5",
                            }, {
                                "text": translate["2-2-6"],
                                "icon": "img/add.png",
                                "id": "2-2-6",
                            }, {
                                "text": translate["2-2-7"],
                                "icon": "img/add.png",
                                "id": "2-2-7",
                            }, {
                                "text": translate["2-2-8"],
                                "icon": "img/add.png",
                                "id": "2-2-8",
                            }]
                        },
                        {
                            "text": "修改",
                            "icon": "img/update.png",
                            "id": "2-3",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [{
                                "text": translate["2-3-1"],
                                "icon": "img/update.png",
                                "id": "2-3-1",
                            }, {
                                "text": translate["2-3-2"],
                                "icon": "img/update.png",
                                "id": "2-3-2",
                            }, {
                                "text": translate["2-3-3"],
                                "icon": "img/update.png",
                                "id": "2-3-3",
                            }, {
                                "text": translate["2-3-4"],
                                "icon": "img/update.png",
                                "id": "2-3-4",
                            }, {
                                "text": translate["2-3-5"],
                                "icon": "img/update.png",
                                "id": "2-3-5",
                            }, {
                                "text": translate["2-3-6"],
                                "icon": "img/update.png",
                                "id": "2-3-6",
                            }, {
                                "text": translate["2-3-7"],
                                "icon": "img/update.png",
                                "id": "2-3-7",
                            }, {
                                "text": translate["2-3-8"],
                                "icon": "img/update.png",
                                "id": "2-3-8",
                            }
                            ]
                        },
                        {
                            "text": "删除",
                            "icon": "img/delete.png",
                            "id": "2-4",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            children: [
                                {
                                    "text": translate["2-4-1"],
                                    "icon": "img/delete.png",
                                    "id": "2-4-1"
                                }, {
                                    "text": translate["2-4-2"],
                                    "icon": "img/delete.png",
                                    "id": "2-4-2"
                                },
                                {
                                    "text": translate["2-4-3"],
                                    "icon": "img/delete.png",
                                    "id": "2-4-3"
                                }, {
                                    "text": translate["2-4-4"],
                                    "icon": "img/delete.png",
                                    "id": "2-4-4"
                                }
                            ]
                        }
                    ]
                },
                {
                    "text": "数据行权限",
                    "icon": "img/tree.png",
                    "state": {
                        "opened": true,
                        "selected": false
                    },
                    "children": [
                        {
                            "text": "查看",
                            "icon": "img/get.png",
                            "id": "3-1",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [
                                {
                                    "text": translate["3-1-1"],
                                    "icon": "img/get.png",
                                    "id": "3-1-1",
                                }, {
                                    "text": translate["3-1-2"],
                                    "icon": "img/get.png",
                                    "id": "3-1-2",
                                },
                                {
                                    "text": translate["3-1-3"],
                                    "icon": "img/get.png",
                                    "id": "3-1-3",
                                }
                            ]
                        },
                        {
                            "text": "添加",
                            "icon": "img/add.png",
                            "id": "3-2",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [{
                                "text": translate["3-2-1"],
                                "icon": "img/add.png",
                                "id": "3-2-1",
                            }, {
                                "text": translate["3-2-2"],
                                "icon": "img/add.png",
                                "id": "3-2-2",
                            }, {
                                "text": translate["3-2-3"],
                                "icon": "img/add.png",
                                "id": "3-2-3",
                            }, {
                                "text": translate["3-2-4"],
                                "icon": "img/add.png",
                                "id": "3-2-4",
                            }]
                        },
                        {
                            "text": "修改",
                            "icon": "img/update.png",
                            "id": "3-3",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [{
                                "text": translate["3-3-1"],
                                "icon": "img/update.png",
                                "id": "3-3-1",
                            }, {
                                "text": translate["3-3-2"],
                                "icon": "img/update.png",
                                "id": "3-3-2",
                            }, {
                                "text": translate["3-3-3"],
                                "icon": "img/update.png",
                                "id": "3-3-3",
                            }, {
                                "text": translate["3-3-4"],
                                "icon": "img/update.png",
                                "id": "3-3-4",
                            }]
                        },
                        {
                            "text": "删除",
                            "icon": "img/delete.png",
                            "id": "3-4",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [{
                                "text": translate["3-4-1"],
                                "icon": "img/delete.png",
                                "id": "3-4-1",
                            }, {
                                "text": translate["3-4-2"],
                                "icon": "img/delete.png",
                                "id": "3-4-2",
                            }]
                        }
                    ]
                },
                {
                    "text": "数据列权限",
                    "icon": "img/tree.png",
                    "state": {
                        "opened": true,
                        "selected": false
                    },
                    "children": [
                        {
                            "text": "查看",
                            "icon": "img/get.png",
                            "id": "4-1",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [
                                {
                                    "text": translate["4-1-1"],
                                    "icon": "img/get.png",
                                    "id": "4-1-1",
                                },
                                {
                                    "text": translate["4-1-2"],
                                    "icon": "img/get.png",
                                    "id": "4-1-2",
                                }
                            ]
                        },
                        {
                            "text": "添加",
                            "icon": "img/add.png",
                            "id": "4-2",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [
                                {
                                    "text": translate["4-2-1"],
                                    "icon": "img/add.png",
                                    "id": "4-2-1",
                                }
                            ]
                        },
                        {
                            "text": "修改",
                            "icon": "img/update.png",
                            "id": "4-3",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [
                                {
                                    "text": translate["4-3-1"],
                                    "icon": "img/get.png",
                                    "id": "4-3-1",
                                }
                            ]
                        },
                        {
                            "text": "删除",
                            "icon": "img/delete.png",
                            "id": "4-4",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [
                                {
                                    "text": translate["4-4-1"],
                                    "icon": "img/delete.png",
                                    "id": "4-4-1",
                                },
                                {
                                    "text": translate["4-4-2"],
                                    "icon": "img/delete.png",
                                    "id": "4-4-2",
                                }
                            ]
                        },
                    ]
                },
                {
                    "text": "请求速率",
                    "icon": "img/tree.png",
                    "state": {
                        "opened": true,
                        "selected": false
                    },
                    "children": [
                        {
                            "text": "查看",
                            "icon": "img/get.png",
                            "id": "5-1",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [
                                {
                                    "text": translate["5-1-1"],
                                    "icon": "img/get.png",
                                    "id": "5-1-1",
                                }
                            ]
                        },
                        {
                            "text": "添加&覆盖",
                            "icon": "img/over.png",
                            "id": "5-2",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [{
                                "text": translate["5-2-1"],
                                "icon": "img/over.png",
                                "id": "5-2-1",
                            }]
                        },
                        {
                            "text": "删除",
                            "icon": "img/delete.png",
                            "id": "5-3",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [{
                                "text": translate["5-3-1"],
                                "icon": "img/delete.png",
                                "id": "5-3-1",
                            }]
                        },
                    ]
                }
            ]
        }]
    }
};

var json_tree_view_1 = $('#json_tree_view');
json_tree_view_1.jstree(json_jstree);

json_tree_view_1.on("changed.jstree", function (e, data) {
    editors[0].set(template[translate[data.node.id]]);
});

var but_open_jstree = $('#json_tree_but_1');
but_open_jstree.on('click', function (event) {
    var triger = event.target.dataset.expanded;
    if (triger === 'true') {
        json_tree_view_1.jstree().open_all();
        console.log(triger);
    } else {
        json_tree_view_1.jstree().close_all();
        console.log(triger);
    }
});

function format(date) {
    var seperator1 = "-";
    var seperator2 = ":";
    var month = date.getMonth() + 1;
    var strDate = date.getDate();
    if (month >= 1 && month <= 9) {
        month = "0" + month;
    }
    if (strDate >= 0 && strDate <= 9) {
        strDate = "0" + strDate;
    }
    return date.getFullYear() + seperator1 + month + seperator1 + strDate + " " + date.getHours() + seperator2 + date.getMinutes() + seperator2 + date.getSeconds();
}

send.on('click', () => {
    var status = $('#status')
    axios.post("api/modify", editors[0].get()).then(res => {
        if (res.data === "error") {
            status.removeClass("success")
            status.addClass("fail")
            status.css("display", "block")
            location.href = "index.html";
        } else {
            $('#response_wrap').empty();
            if (res.data.message === "FAIL") {
                status.removeClass("success")
                status.addClass("fail")
                status.css("display", "block")
                jsonTree.create({}, $('#response_wrap')[0]);
            } else {
                status.removeClass("fail")
                status.addClass("success")
                status.css("display", "block")
                if (!res.data.data) {
                    jsonTree.create({}, $('#response_wrap')[0]);
                } else {
                    jsonTree.create(res.data.data, $('#response_wrap')[0]);
                }
            }
        }
        status.html(format(new Date()))
    })
})

var container = document.querySelector(".step_1 .json_editor_view_1");
var options = {};
editors[0] = new JSONEditor(container, options);

var json_j = {
    "Array": [1, 2, 3],
    "Array2": [1, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3],
    "Boolean": true,
    "Null": null,
    "Number": 123,
    "Object": {
        "a": "b",
        "c": "d",
    },
    "String": "🌟欢迎使用Authz后台json编辑器🌟"
};

editors[0].set(json_j);

setTimeout(() => {
    axios.get("api/info").then(res => {
        if (res.data) {
            var info = res.data;
            $('#info').html(`${info.prefix}    -   ${info.application}`)
        }
    })
}, 10)

