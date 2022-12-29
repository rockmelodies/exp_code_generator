'''
coding:utf-8
@Software:PyCharm
@Time:2022/12/22 15:46
@Author:尘心||rocky
'''

import os
from string import Template

from dotenv import find_dotenv, load_dotenv

load_dotenv(find_dotenv('.env'))
env_dist = os.environ


def generate():
    className = env_dist.get('CLASSNAME')
    vul_id = env_dist.get('VUL_ID')
    vul_date = env_dist.get('VUL_DATE')
    create_date = env_dist.get('CREATEDATE')
    update_date = env_dist.get('UPDATEDATE')
    app_name = env_dist.get('APP_NAME')
    vul_name = env_dist.get('VUL_NAME')
    vul_num = env_dist.get('VUL_NUM')
    cve_num = env_dist.get('CVE_NUM')
    cnvd_num = env_dist.get('CNVD_NUM')
    vul_type = env_dist.get('VUL_TYPE')
    poc_category = env_dist.get('POC_CATEGORY')
    severity = env_dist.get('SEVERITY')
    reqAuth = env_dist.get('REQAUTH')
    fingerprintNames = env_dist.get('FINGERPRINT_NAMES')
    appPowerLink = env_dist.get('APP_POWER_LINK')
    desc = env_dist.get('DESC')
    suggest = env_dist.get('SUGGEST')
    hasExp = env_dist.get('HASEXP')
    targets = env_dist.get('TARGETS')
    suricata_rules = env_dist.get('SURICATA_RULES')
    command = env_dist.get('COMMAND')
    file_path = env_dist.get('FILE_PATH')
    headers = env_dist.get('HEADERS')
    keyword = env_dist.get('KEYWORD')
    method = env_dist.get('METHOD')
    payload_data = env_dist.get('PAYLOAD_DATA')
    attack_payload_data = env_dist.get('ATTACK_PAYLOAD_DATA')
    references = env_dist.get('REFERENCES')
    uri = env_dist.get('URI')
    app_main_port= env_dist.get('APP_MAIN_PORT')
    appVersion = env_dist.get('APPVERSION')
    attack_uri = env_dist.get('ATTACK_URI')
    filePath = r'pocs/%s.py' % className
    class_file = open(filePath, 'w')
    lines = []

    # 模版文件
    template_file = open(r'pocsuite3_code.template', 'r')
    tmpl = Template(template_file.read())
    # 模版替换
    # substitute 会报错 没有匹配到的数值；safe_substitute 会将没有匹配到的数据 原封不动展示出来
    lines.append(tmpl.safe_substitute(
        REFERENCES=references,
        CLASSNAME=className,
        VUL_ID=vul_id,
        VUL_DATE=vul_date,
        CREATEDATE=create_date,
        UPDATEDATE=update_date,
        APP_NAME=app_name,
        VUL_NAME=vul_name,
        VUL_NUM=vul_num,
        CVE_NUM=cve_num,
        CNVD_NUM=cnvd_num,
        VUL_TYPE=vul_type,
        POC_CATEGORY=poc_category,
        SEVERITY=severity,
        REQAUTH=reqAuth,
        FINGERPRINT_NAMES=fingerprintNames,
        APP_POWER_LINK=appPowerLink,
        DESC=desc,
        SUGGEST=suggest,
        HASEXP=hasExp,
        TARGETS=targets,
        SURICATA_RULES=suricata_rules,
        COMMAND=command,
        FILE_PATH=file_path,
        HEADERS=headers,
        KEYWORD=keyword,
        METHOD=method,
        PAYLOAD_DATA=payload_data,
        URI=uri,
        ATTACK_PAYLOAD_DATA=attack_payload_data,
        APPVERSION=appVersion,
        ATTACK_URI=attack_uri,
        APP_MAIN_PORT=app_main_port,
        EXPIRE_DATE='06JUN14'))
    # 0.将生成的代码写入文件
    class_file.writelines(lines)
    class_file.close()


if __name__ == '__main__':
    generate()
