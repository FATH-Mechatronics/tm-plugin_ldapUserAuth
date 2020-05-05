const fs = require('fs');
const path = require('path');
const ActiveDirectory = require('activedirectory');

const CONFIG_PATH = path.join(__dirname, "ldapUserSignon.json");

const _baseConfig = {
    autoCreateUser: true,
    defaultRoles: [1],
    fallbackToLocal: true,
    activedirectory:{
        url: "",
        baseDN: "",
        username: "",
        password: "",
        requieredGroup: ""
    }
};

var _axios = null;
var _ws = null;
var _basepath = null;
var _ad = null;

function _getConfig() {
    return new Promise((resolve, reject) => {
        resolve(_getConfigSync());
    });
}

function _getConfigSync() {
    try {
        let data = fs.readFileSync(CONFIG_PATH);
        return JSON.parse(data.toString('utf-8'));
    }catch{
        return _baseConfig;
    }
}

function _authenticate(user, pass) {
    return new Promise((resolve, reject) => {
        let config = _getConfigSync();
        _ad.authenticate(user, pass, (err, auth) => {
            if (err) {
                console.error("AD Auth Err", JSON.stringify(err));
                resolve(false);
                return;
            }
            if(auth){
                if (config.activedirectory.requieredGroup === ""){
                    resolve(true);
                    return;
                }

                _ad.getGroupMembershipForUser(user, (err, groups) =>{
                    if(err){
                        console.error("AD Group Err", JSON.stringify(err));
                        resolve(false);
                        return;
                    }
                    for (var key in groups){
                        if(groups[key].cn === config.activedirectory.requieredGroup){
                            resolve(true);
                            return;
                        }
                    }
                    resolve(false);
                });
            }else{
                resolve(false);
            }
        });
    });
}

module.exports = {
    init: (config) => {
        _axios = config.axios;
        _ws = config.ws;
        _basepath = config.basepath;
        _ad = new ActiveDirectory(_getConfigSync().activedirectory);
    },

    autoCreateUser: () => {
        return _getConfigSync().autoCreateUser;
    },

    defaultRoles: () => {
        return _getConfigSync().defaultRoles;
    },

    fallbackToLocal: () => {
        return _getConfigSync().fallbackToLocal;
    },

    authenticate: (user, pass) => {
        return _authenticate(user, pass);
    },

    name: () => "ldapUserSignon",

    getConfig: () => {
        return new Promise(resolve => {
            _getConfig().then(conf => {
                resolve(conf);
            }).catch(e => {
                resolve(_baseConfig);
            });
        });
    },

    writeConfig: (config) => {
        fs.writeFile(CONFIG_PATH, JSON.stringify(config), (err) => {
            if (err) {
                console.error("Store Config", err);
            }
        });
    },

    getHelp: () => {
        return '{\n' +
            '    autoCreateUser: true,\n' +
            '    defaultRoles: [ 1 ],\n' +
            '    fallbackToLocal: true\n' +
            '    activedirectory: {\n' +
            '        url: \'ldap://dc.domain.com\',\n' +
            '        baseDN: \'dc=domain,dc=com\',\n' +
            '        username: \'username@domain.com\',\n' +
            '        password: \'password\',\n'+
            '        equieredGroup: \'GRP\'\n' +
            '    }\n'+
            '}'
    }
};
