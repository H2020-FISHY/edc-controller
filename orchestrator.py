import os
import subprocess
import threading
import time
import json
from flask import *
from rabbit_consumer import RMQsubscriber
from werkzeug.utils import secure_filename
import shutil

POLICIES_DIR = 'Policy'
OUTPUT_DIR = 'output'
TMP_DIR = '/tmp'

app = Flask(__name__)

app.secret_key = os.urandom(16)

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
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(POLICIES_DIR, filename))
            resp = make_response(redirect(url_for('home')))
            resp.set_cookie('policy_filename', filename)
            return resp
    return render_template('upload_policy.html')


@app.route('/select_hspl', methods=['GET', 'POST'])
def select_hspl():
    if request.method == 'GET':
        policies = os.listdir(POLICIES_DIR)
        return render_template('select_policy.html', policies=policies)

    if request.method == 'POST':
        if (not 'policy' in request.form):
            return 'Error, bad data'

        policy_filename = secure_filename(request.form['policy'])
        if (not os.path.isfile(os.path.join(POLICIES_DIR, policy_filename))):
            return 'Error, invalid selection'

        resp = make_response(redirect(url_for('home')))
        resp.set_cookie('policy_filename', policy_filename)
        return resp


@app.route('/upload_database', methods=['GET', 'POST'])
def upload_database():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            # flash('ERROR: No file part')
            return redirect(url_for('home'))
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            # flash('ERROR: No selected file')
            return redirect(url_for('home'))
        if file:
            # RCE by design
            # it override completely the company database
            return 'disabled for security reasons'
            assert(file.filename == 'company_database.py')
            file_path = 'src/company_database.py'
            file.save(file_path)
            return redirect(url_for('home'))
    return render_template('upload_database.html')


@app.route('/refinement', methods=['GET', 'POST'])
def execute_refinement():
    policy_filename = request.cookies.get('policy_filename')
    print(policy_filename)
    if(not policy_filename):
        return 'Error, you need to upload or select a policy file to start'
    policy_filename = os.path.join(
        POLICIES_DIR, secure_filename(policy_filename))
    if (not os.path.isfile(policy_filename)):
        return 'Error, selected policy file not found'

    if request.method == 'GET':

        # print('Policy file: ', policy_filename)

        # database_local_time = time.ctime(
        #     os.stat('src/company_database.p').st_mtime)
        # print("company_database.py modified last time: "+database_local_time)

        suitable_devices_tmp_filename = os.path.join(
            TMP_DIR, os.urandom(8).hex() + '.json')

        p = subprocess.run(
            ["python", "src/refinement.py", policy_filename, '--paths-info', suitable_devices_tmp_filename],
            capture_output=True)

        if (p.returncode != 0):
            print(p.stdout.decode(), flush=True)
            return 'Error, something went wrong'

        devices = json.load(open(suitable_devices_tmp_filename))
        os.remove(suitable_devices_tmp_filename)

        return render_template('select_devices.html', list_val=devices)
    elif request.method == 'POST':
        devices = request.json

        filename_selected_devices = os.path.join(
            TMP_DIR, os.urandom(8).hex() + '.json')

        intermediate_file = os.path.join(
            TMP_DIR, os.urandom(8).hex() + '.json')

        json.dump(devices, open(filename_selected_devices, 'w'))
        p = subprocess.run(
            ["python", "src/refinement.py", policy_filename, '--choosen-conf', filename_selected_devices, '-o', intermediate_file],
            capture_output=True)

        os.remove(filename_selected_devices)

        if (p.returncode != 0):
            print(p.stdout.decode(), flush=True)
            return 'Error, something went wrong'

        rules_output_dir = os.path.join(
            OUTPUT_DIR, f'{os.path.basename(policy_filename).split(".")[0]}_{int(time.time())}{os.urandom(6).hex()}')

        p = subprocess.run(
            ["python", "src/converter.py", intermediate_file, rules_output_dir], capture_output=True)

        if (p.returncode != 0):
            print(p.stdout.decode(), flush=True)
            return 'Error, something went wrong'

        return jsonify(dirname=os.path.basename(rules_output_dir))

    else:
        return 'generic error\n'


@app.route('/refinement_no_gui', methods=['GET', 'POST'])
def execute_refinement_no_gui():
    policy_filename = request.cookies.get('policy_filename')
    print(policy_filename)
    if(not policy_filename):
        return 'Error, you need to upload or select a policy file to start'
    policy_filename = os.path.join(
        POLICIES_DIR, secure_filename(policy_filename))
    if (not os.path.isfile(policy_filename)):
        return 'Error, selected policy file not found'

    if request.method == 'GET':

        # print('Policy file: ', policy_filename)

        # database_local_time = time.ctime(
        #     os.stat('src/company_database.p').st_mtime)
        # print("company_database.py modified last time: "+database_local_time)

        suitable_devices_tmp_filename = os.path.join(
            TMP_DIR, os.urandom(8).hex() + '.json')

        p = subprocess.run(
            ["python", "src/refinement.py", policy_filename, '--paths-info', suitable_devices_tmp_filename],
            capture_output=True)

        if (p.returncode != 0):
            print(p.stdout.decode(), flush=True)
            return 'Error, something went wrong'

        devices = json.load(open(suitable_devices_tmp_filename))

        #print(devices)

        os.remove(suitable_devices_tmp_filename)

        return devices
    elif request.method == 'POST':
        devices = request.json

        #print(devices)

        filename_selected_devices = os.path.join(
            TMP_DIR, os.urandom(8).hex() + '.json')

        intermediate_file = os.path.join(
            TMP_DIR, os.urandom(8).hex() + '.json')

        json.dump(devices, open(filename_selected_devices, 'w'))
        p = subprocess.run(
            ["python", "src/refinement.py", policy_filename, '--choosen-conf', filename_selected_devices, '-o', intermediate_file],
            capture_output=True)

        os.remove(filename_selected_devices)

        if (p.returncode != 0):
            print(p.stdout.decode(), flush=True)
            return 'Error, something went wrong'

        rules_output_dir = os.path.join(
            OUTPUT_DIR, f'{os.path.basename(policy_filename).split(".")[0]}_{int(time.time())}{os.urandom(6).hex()}')

        p = subprocess.run(
            ["python", "src/converter.py", intermediate_file, rules_output_dir], capture_output=True)

        if (p.returncode != 0):
            print(p.stdout.decode(), flush=True)
            return 'Error, something went wrong'

        # returns a json from a dict object {key: value} the name of the directory
        # containing the produced RuleInstance files as key, and as value the list of the names of those files
        return {os.path.basename(rules_output_dir): os.listdir(rules_output_dir)}

    else:
        return 'generic error\n'


@ app.route('/result', methods=['GET'])
def get_result_list():
    if request.method == 'GET':
        result_files = os.listdir(OUTPUT_DIR)
        return render_template('result_list.html', result_files=result_files)
    return 'generic error\n'


@ app.route('/result/<dirname>', methods=['GET'])
def get_result(dirname):
    if request.method == 'GET':
        output_dir = os.path.join(OUTPUT_DIR, secure_filename(dirname))
        if (not os.path.isdir(output_dir)):
            return 'Not found, please run again the script'

        rules_files = os.listdir(output_dir)
        return render_template('result.html', rules_files=rules_files, dirname=os.path.basename(output_dir))
    return 'generic error\n'


@ app.route('/result/<dirname>/<rulename>', methods=['GET'])
def download_rule(dirname, rulename):
    if request.method == 'GET':
        rule_filename = os.path.join(OUTPUT_DIR, secure_filename(dirname),
                                     secure_filename(rulename))
        if (not os.path.isfile(rule_filename)):
            return 'Not found'

        return send_file(rule_filename)
    return 'generic error\n'


@ app.route('/download/<dirname>', methods=['GET'])
def download_zip(dirname):
    if request.method == 'GET':
        output_dir = os.path.join(OUTPUT_DIR, secure_filename(dirname))
        if (not os.path.isdir(output_dir)):
            return 'Not found'

        archive_file = os.path.join(TMP_DIR, os.path.basename(output_dir))
        archive_file = shutil.make_archive(archive_file, 'zip', output_dir)

        return send_file(archive_file, as_attachment=True)
    return 'generic error\n'


@ app.route('/', methods=['GET'])
def home():
    selected_policy = request.cookies.get('policy_filename')
    return render_template('home.html', selected_policy=selected_policy)


def cr_responder():
    """Runs the Central Repository response pipeline, that is the RabbitMQ consumer and producer"""
    queueName = 'refeng'
    key = 'policies.create'
    notification_consumer_config = {'host': 'fishymq.xlab.si',
                                    'port': 45672,
                                    'exchange' : 'tasks',
                                    'login':'tubs',
                                    'password':'sbut'}

    init_rabbit = RMQsubscriber(queueName, key, notification_consumer_config)
    init_rabbit.setup()

def main_old():
    app.run(host='0.0.0.0', port=5000, debug=False)

def main():
    thread = threading.Thread(target=cr_responder)
    thread.start()
    app.run(host='0.0.0.0', port=5000, debug=False)
    thread.join()

if __name__ == '__main__':
    main()