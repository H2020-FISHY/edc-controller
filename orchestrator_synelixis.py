import os
import subprocess
import glob
import time
import platform
import ast
import requests
from io import BytesIO
from zipfile import ZipFile
from flask import *
from werkzeug.utils import secure_filename

SERVER_FOLDER = '.' + os.sep
UPLOAD_FOLDER = '.' + os.sep + 'Policy'
UPLOAD_FOLDER_SRC = '.' + os.sep + 'src'
UPLOAD_FOLDER_LOW_LEVEL = '.' + os.sep + 'Low_Level_Policy'
DOWNLOAD_FOLDER = '.' + os.sep + 'RuleInstance'
ALLOWED_EXTENSIONS = {'xml', 'py'}

app = Flask(__name__)
app.config['SERVER_FOLDER'] = SERVER_FOLDER
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['UPLOAD_FOLDER_SRC'] = UPLOAD_FOLDER_SRC
app.config['UPLOAD_FOLDER_LOW_LEVEL'] = UPLOAD_FOLDER_LOW_LEVEL
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER
app.config['PROPAGATE_EXCEPTIONS'] = True

info_refinement = False
execution_refinement = False
execution_converter = False
execution_translator = False
execute_all = 0
hspl_list = []

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def modification_date(path_to_file):
    if platform.system() == 'Windows':
        return os.path.getmtime(path_to_file)
    else:
        stat = os.stat(path_to_file)
        return stat.st_mtime


@app.route('/upload_hspl', methods=['GET', 'POST'])
def upload_hspl():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('ERROR: No file part')
            return redirect(url_for('home'))
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('ERROR: No selected file')
            return redirect(url_for('home'))
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('home'))
    return redirect(url_for('home'))


@app.route('/upload_database', methods=['GET', 'POST'])
def upload_database():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('ERROR: No file part')
            return redirect(url_for('home'))
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('ERROR: No selected file')
            return redirect(url_for('home'))
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER_SRC'], filename)
            file.save(file_path)
            return redirect(url_for('home'))
    return render_template('Upload_database.html')


@app.route('/get_info_refinement', methods=['GET', 'POST'])
def get_info_refinement():
    global info_refinement
    global execution_refinement
    global hspl_list
    if request.method == 'GET':
        if not os.listdir(app.config['UPLOAD_FOLDER']):
            return 'ERROR: you have not uploaded any .xml file\n'
        policy_list_of_files = glob.glob(os.path.join(app.config['UPLOAD_FOLDER'], '*.xml'))
        policy_latest_file = max(policy_list_of_files, key=os.path.getctime)
        policy_local_time = time.ctime(modification_date(policy_latest_file))
        print("File XML modified last time: " + policy_local_time)
        database_list_of_files = glob.glob(os.path.join(app.config['UPLOAD_FOLDER_SRC'], 'company_database.py'))
        database_latest_file = max(database_list_of_files, key=os.path.getctime)
        database_local_time = time.ctime(modification_date(database_latest_file))
        print("company_database.py modified last time: " + database_local_time)
        os.chdir('./src')
        devices = subprocess.check_output(["python", "get_info_refinement.py", '.' + policy_latest_file])
        os.chdir('../')
        info_refinement = True
        devices = devices.decode()
        devices = devices.split('}')[0] + '}'
        devices = ast.literal_eval(devices)
        hspl_list = devices.keys()
        return render_template('Info_refinement.html', list_val=devices)
    elif request.method == 'POST':
        devices = {}
        for hspl in hspl_list:
            hspl_devices = request.form.getlist(hspl)
            if len(hspl_devices) == 0:
                flash('ERROR: Select at least 1 device for hspl.')
                return redirect(url_for('home'))
            devices[hspl] = hspl_devices
        response = requests.post('http://localhost:5000/execute_refinement', json=devices)
        if response.status_code == 200:
            execution_refinement = True
            return redirect(url_for('home'))
        else:
            return 'generic error.\n'
    else:
        return 'generic error\n'


@app.route('/execute_refinement', methods=['POST'])
def execute_refinement():
    global info_refinement
    if request.method == 'POST' and info_refinement:
        policy_list_of_files = glob.glob(os.path.join(app.config['UPLOAD_FOLDER'], '*.xml'))
        policy_latest_file = max(policy_list_of_files, key=os.path.getctime)
        policy_local_time = time.ctime(modification_date(policy_latest_file))
        print("File XML modified last time: " + policy_local_time)
        database_list_of_files = glob.glob(os.path.join(app.config['UPLOAD_FOLDER_SRC'], 'company_database.py'))
        database_latest_file = max(database_list_of_files, key=os.path.getctime)
        database_local_time = time.ctime(modification_date(database_latest_file))
        print("company_database.py modified last time: " + database_local_time)
        os.chdir('./src')
        print(request.json)
        subprocess.call(["python", "execute_refinement.py", '.' + policy_latest_file, str(request.json)])
        os.chdir('../')
        return 'execute_refinement.py executed\n'
    else:
        return 'First execute get_info_refinement.\n'


@app.route('/refinement_no_gui', methods=['GET'])
def refinement_no_gui():
    if request.method == 'GET':
        if not os.listdir(app.config['UPLOAD_FOLDER']):
            flash('ERROR: No HSPL file uploaded.')
            return redirect('home')
        policy_list_of_files = glob.glob(os.path.join(app.config['UPLOAD_FOLDER'], '*.xml'))
        policy_latest_file = max(policy_list_of_files, key=os.path.getctime)
        policy_local_time = time.ctime(modification_date(policy_latest_file))
        print("File XML modified last time: " + policy_local_time)
        database_list_of_files = glob.glob(os.path.join(app.config['UPLOAD_FOLDER_SRC'], 'company_database.py'))
        database_latest_file = max(database_list_of_files, key=os.path.getctime)
        database_local_time = time.ctime(modification_date(database_latest_file))
        print("company_database.py modified last time: " + database_local_time)
        os.chdir('./src')
        subprocess.call(["python", "refinement_no_gui.py", '.' + policy_latest_file])
        os.chdir('../')
        return redirect(url_for('home'))
    return 'generic error\n'


@app.route('/converter', methods=['GET'])
def converter():
    global execution_converter
    if request.method == 'GET':
        os.chdir('./src')
        subprocess.call(["python", "converter.py", '../Intermediate.txt'])
        os.chdir('../')
        if os.path.exists(app.config['DOWNLOAD_FOLDER']):
            list_of_files = [os.path.basename(x) for x in
                             glob.glob(os.path.join(app.config['DOWNLOAD_FOLDER'], '*.xml'))]
            execution_converter = True
            if execute_all == 0:
                flash('Rule Instance files generated: ' + str(list_of_files))
            return redirect(url_for('home'))
        else:
            flash('ERROR: No RuleInstance folder found.')
            return redirect(url_for('home'))
    return 'generic error\n'


@app.route('/download/<filename>', methods=['GET'])
def download(filename):
    if request.method == 'GET':
        return send_file(os.path.join(os.getcwd(), app.config["DOWNLOAD_FOLDER"], filename))
    return 'generic error\n'


@app.route('/', methods=['GET', 'POST'])
def home():
    global execution_refinement
    global execute_all
    global execution_translator
    if request.method == 'POST':
        if 'hspl' in request.form:
            return redirect(url_for('upload_hspl'))
        elif 'database' in request.form:
            return redirect(url_for('upload_database'))
        elif 'info_refinement' in request.form:
            return redirect(url_for('get_info_refinement'))
        elif 'intermediate' in request.form:
            return send_file(os.path.join(os.getcwd(), app.config["SERVER_FOLDER"], 'Intermediate.txt'),
                             as_attachment=True)
        elif 'converter' in request.form:
            return redirect(url_for('converter'))
        elif 'rule_instances' in request.form:
            target = os.path.join(os.getcwd(), app.config["DOWNLOAD_FOLDER"])
            stream = BytesIO()
            with ZipFile(stream, 'w') as zf:
                for file in glob.glob(os.path.join(target, '*.xml')):
                    zf.write(file, os.path.basename(file))
            stream.seek(0)
            return send_file(stream, as_attachment=True, download_name='RuleInstances.zip')
        elif 'low_level' in request.form:
            target = os.path.join(os.getcwd(), app.config["UPLOAD_FOLDER_LOW_LEVEL"])
            stream = BytesIO()
            with ZipFile(stream, 'w') as zf:
                for file in glob.glob(os.path.join(target, '*.txt')):
                    zf.write(file, os.path.basename(file))
            stream.seek(0)
            return send_file(stream, as_attachment=True, download_name='LowLevelPolicies.zip')
        elif 'execute_all' in request.form:
            execute_all = 1

            policy_list_of_files = glob.glob(os.path.join('../../temp/', 'HSPL*.xml'))
            policy_latest_file = max(policy_list_of_files, key=os.path.getctime)

            files = {'file': open(str(policy_latest_file), 'rb')}
            requests.post('http://localhost:5000/upload_hspl', files=files)
    else:
        if execute_all == 1:
            execute_all = 2

            os.chdir('./src')
            malicious_list_of_files = glob.glob(os.path.join('../../../temp/', '*.info'))
            malicious_latest_file = max(malicious_list_of_files, key=os.path.getctime)

            subprocess.call(["python", "database_inserter.py", str(malicious_latest_file)])
            os.chdir('../')

            return redirect(url_for('refinement_no_gui'))
        elif execute_all == 2:
            execute_all = 3
            return redirect(url_for('converter'))
        elif execute_all == 3:
            for filename in os.listdir(app.config['DOWNLOAD_FOLDER']):
                file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], filename)
                files = {'file': open(file_path, 'rb')}
                r = requests.post('http://127.0.0.1:8080/translator', files=files, data={'upload': 'Upload'})
                if 'File uploaded correctly' in r.text:
                    r = requests.post('http://127.0.0.1:8080/translator',
                                      data={'translate': 'Translate', 'destnsf': ''})
                    if not ('html' in r.text):
                        execution_translator = True
                        filename = filename.replace('RuleInstance.xml', 'LowLevel.txt')
                        file_path = os.path.join(app.config['UPLOAD_FOLDER_LOW_LEVEL'], filename)
                        with open(file_path, "w") as fp:
                            fp.write(r.text)
                        fp.close()
                    else:
                        flash('ERROR: Generic Translator error.')
                        execute_all = 0
                        return redirect(url_for('home'))
            for filename in os.listdir(app.config['UPLOAD_FOLDER_LOW_LEVEL']):
                file_path = os.path.join(app.config['UPLOAD_FOLDER_LOW_LEVEL'], filename)
                if "iptables" in file_path.lower() or "ethereum" in file_path.lower():
                    subprocess.call(["python", "../../temp/sender.py", file_path])
        else:
            return render_template('Home.html', refinement=execution_refinement, converter=execution_converter, translator=execution_translator)
    return render_template('Home.html', refinement=execution_refinement, converter=execution_converter, translator=execution_translator)


if __name__ == '__main__':
    # if os.path.exists(app.config['UPLOAD_FOLDER']):
    #     for f in os.listdir(app.config['UPLOAD_FOLDER']):
    #         os.remove(os.path.join(app.config['UPLOAD_FOLDER'], f))
    if os.path.exists(app.config['UPLOAD_FOLDER_LOW_LEVEL']):
        for f in os.listdir(app.config['UPLOAD_FOLDER_LOW_LEVEL']):
            os.remove(os.path.join(app.config['UPLOAD_FOLDER_LOW_LEVEL'], f))
    app.run(host='0.0.0.0', port=5000, debug=False)
