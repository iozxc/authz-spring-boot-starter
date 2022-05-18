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
            "text": "Authz Modifier",
            "icon": "img/tree.png",
            "state": {
                "opened": true,
                "selected": false
            },
            "children": [
                {
                    "text": "API相关操作",
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
                                "text": "查看所有API权限",
                                "icon": "img/get.png",
                                "id": "1-1-1",
                            }, {
                                "text": "查看某方法的所有API权限",
                                "icon": "img/get.png",
                                "id": "1-1-2",
                            }, {
                                "text": "查看某API所有方法的权限",
                                "icon": "img/get.png",
                                "id": "1-1-3",
                            }, {
                                "text": "查看具体API的权限",
                                "icon": "img/get.png",
                                "id": "1-1-4",
                            }]
                        },
                        {
                            "text": "添加",
                            "icon": "img/add.png",
                            "id": "1-2",
                            "operate": "给API添加权限",
                            "state": {
                                "opened": false,
                                "selected": false
                            },
                            "children": [{
                                "text": "添加完整的权限",
                                "icon": "img/add.png",
                                "id": "1-2-1",
                            }, {
                                "text": "添加【需要】的角色（require role）",
                                "icon": "img/add.png",
                                "id": "1-2-2",
                            }, {
                                "text": "添加【排除】的角色（exclude role）",
                                "icon": "img/add.png",
                                "id": "1-2-3",
                            }, {
                                "text": "添加【需要】的权限（require permission）",
                                "icon": "img/add.png",
                                "id": "1-2-4",
                            }, {
                                "text": "添加【排除】的权限（exclude permission）",
                                "icon": "img/add.png",
                                "id": "1-2-5",
                            }]
                        }
                    ]
                },
                {
                    "text": "API参数相关操作",
                    "icon": "img/tree.png",
                    "state": {
                        "opened": false,
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
                                "text": "查看某个API所有的参数权限",
                                "icon": "img/get.png",
                                "id": "2-1-1",
                            }, {
                                "text": "查看某个API某个参数的权限",
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
                                "text": "添加PATH参数的【ROLE】权限 - range",
                                "icon": "img/add.png",
                                "id": "2-2-1",
                            }, {
                                "text": "添加PATH参数的【ROLE】权限 - resources",
                                "icon": "img/add.png",
                                "id": "2-2-2",
                            }, {
                                "text": "添加Request Param参数的【ROLE】权限 - range",
                                "icon": "img/add.png",
                                "id": "2-2-3",
                            }, {
                                "text": "添加Request Param参数的【ROLE】权限 - resources",
                                "icon": "img/add.png",
                                "id": "2-2-4",
                            }, {
                                "text": "添加PATH参数的【PERMISSION】权限 - range",
                                "icon": "img/add.png",
                                "id": "2-2-5",
                            }, {
                                "text": "添加PATH参数的【PERMISSION】权限 - resources",
                                "icon": "img/add.png",
                                "id": "2-2-6",
                            }, {
                                "text": "添加Request Param参数的【PERMISSION】权限 - range",
                                "icon": "img/add.png",
                                "id": "2-2-7",
                            }, {
                                "text": "添加Request Param参数的【PERMISSION】权限 - resources",
                                "icon": "img/add.png",
                                "id": "2-2-8",
                            }]
                        }
                    ]
                }
            ]
        }]
    }
};

var json_tree_view_1 = $('#json_tree_view_1');
json_tree_view_1.jstree(json_jstree);

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

    "添加PATH参数的ROLE权限 - range": {
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
    "添加PATH参数的ROLE权限 - resources": {
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
    "添加Request Param参数的ROLE权限 - range": {
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
    "添加Request Param参数的ROLE权限 - resources": {
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
    "添加PATH参数的PERMISSION权限 - range": {
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
    "添加PATH参数的PERMISSION权限 - resources": {
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
    "添加Request Param参数的PERMISSION权限 - range": {
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
    "添加Request Param参数的PERMISSION权限 - resources": {
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

    "修改PATH参数的ROLE权限 - range": {
        "operate": "UPDATE",
        "target": "PATH_VAR_ROLE",
        "method": "",
        "api": "",
        "value": "",
        "index": 0,
        "range": [""]
    }


}
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

send.on('click', () => {
    axios.post("api/modify", editors[0].get()).then(res => {
        if (res.data === "error") {
            location.href = "index.html";
        } else {
            $('#response_wrap').empty();
            if (res.data.message === "FAIL") {
                jsonTree.create(res.data, $('#response_wrap')[0]);
            } else {
                if (!res.data.data) {
                    jsonTree.create(res.data, $('#response_wrap')[0]);
                } else {
                    jsonTree.create(res.data.data, $('#response_wrap')[0]);
                }
            }
        }
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

function f_show_obj_in_console() {
    var json = editors[0].get();
    console.log(json);
}

var show_obj_in_console = document.querySelector('#show_obj_in_console');
var clear_console = document.querySelector('#clear_console');
show_obj_in_console.addEventListener('click', f_show_obj_in_console);
clear_console.addEventListener('click', function () {
    console.clear();
    response.html('');
});
