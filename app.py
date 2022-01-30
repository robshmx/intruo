import time
import os
import requests
import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from intruo import Intruo, IntruoConfiguration, IntruoModules
from flask import Flask, render_template, jsonify, request, send_file
from nanoid import generate

DEBUG_INTRUO = True

template_folder = os.path.join(os.getcwd(), 'web', 'templates')
static_folder = os.path.join(os.getcwd(), 'web', 'static')
app = Flask(
    import_name='__name__',
    template_folder=template_folder,
    static_url_path='/static',
    static_folder=static_folder,
)
app.config['SECRET_KEY'] = 'INTRUO_SECRET_KEY'
app.config ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///intruo.db'
db = SQLAlchemy(app)


class IntruoDB(db.Model):
   id = db.Column(db.Integer, primary_key = True)
   public_id = db.Column(db.Text())
   domain = db.Column(db.Text())
   time_init = db.Column(db.Text())  
   time_end = db.Column(db.Text())
   result = db.Column(db.Text())

   def __init__(self, public_id, domain, time_init, time_end, result):
       self.public_id = public_id
       self.domain = domain
       self.time_init = time_init
       self.time_end = time_end
       self.result = result

db.create_all()

# Routing Main
@app.route('/', methods=['GET'])
def main():
    return render_template('main.html')

# Routing Result
@app.route('/resultado/<public_id>', methods=['GET'])
def result(public_id):
    data = IntruoDB.query.filter_by(public_id=public_id).first()
    result = json.loads(data.result)
    return render_template('result.html', result=result)

# Routing API
@app.route('/api/check_configuration', methods=['GET'])
def api_configuration_check():
    configuration = IntruoConfiguration.check_configuration()
    for item in configuration:
        if configuration[item]['result'] == False:
            return jsonify(configuration), 400

    return jsonify(configuration)

@app.route('/api/configuration/install/driver', methods=['POST'])
def api_configuration_install_driver():
    data = request.files
    if not 'driver' in data:
        return jsonify({'error': 'No podemos instalar el driver. Intenta reinstalando INTRUO.'}), 400
    
    driver = request.files['driver']
    driver.save(os.path.join(os.getcwd(), 'utils', 'chromedriver.exe'))


    return jsonify(True)

@app.route('/api/modules', methods=['GET'])
def api_modules():
    result = []
    for module in IntruoModules:
        result.append(module.value.split('__')[1].replace('_', ' '))

    return jsonify(result)

@app.route('/api/module/page_online', methods=['POST'])
def api_module_is_up():
    data = request.json
    domain = data['domain']

    try:
        r = requests.get(domain)
    except requests.exceptions.RequestException as e:
        print(e)
        return jsonify('La página no está disponbile.'), 400

    return jsonify(True)

@app.route('/api/modules/run', methods=['POST'])
def api_module_run():
    data = request.json
    domain = data['domain']
    modules = data['modules']
    intruo = Intruo(domain=domain, debug=DEBUG_INTRUO)
    intruo.module__https()
    for module in modules:
        module = module.replace(' ',  '_')
        module = f'module__{module.lower()}'
        getattr(intruo, module)()

    save_result = intruo.action_generate_results()
    result = intruo.result
    intruo_record = IntruoDB(
        public_id=generate('1234567890abcdefghijkmnopqrstuvwxyz', 10),
        domain=domain,
        time_init=result['time_execution']['init'],
        time_end=result['time_execution']['end'],
        result=json.dumps(save_result)
    )
    db.session.add(intruo_record)
    db.session.commit()    

    return jsonify(intruo_record.public_id)

@app.route('/api/module/screenshot', methods=['POST'])
def api_module_screenshot():
    data = request.json
    domain = data['domain']
    intruo = Intruo(domain=domain, debug=DEBUG_INTRUO)
    filename = intruo.action_get_screenshoot()

    return jsonify(filename)

@app.route('/api/download/json/<public_id>', methods=['GET'])
def api_download_json_result(public_id):
    data = IntruoDB.query.filter_by(public_id=public_id).first()

    json_file = json.loads(data.result)['json']
    return send_file(os.path.join(os.getcwd(), 'web', 'static', 'results', 'json', json_file), as_attachment=True, download_name=json_file)

@app.route('/api/download/html/<public_id>', methods=['GET'])
def api_download_html_result(public_id):
    data = IntruoDB.query.filter_by(public_id=public_id).first()

    html_file = json.loads(data.result)['html']
    return send_file(os.path.join(os.getcwd(), 'web', 'static', 'results', 'html', html_file), as_attachment=True, download_name=html_file)

@app.route('/api/scan/history', methods=['GET'])
def api_scan_history():
    history = IntruoDB.query.all()

    result = []
    for row in history:
        result.append({
            'public_id': row.public_id,
            'domain': row.domain,
            'time_init': row.time_init,
            'time_end': row.time_end,
            'result': json.loads(row.result)
        })

    return jsonify(result)

@app.route('/api/scan/delete/<public_id>', methods=['DELETE'])
def api_scan_delete(public_id):
    data = IntruoDB.query.filter_by(public_id=public_id).first()
    data_files = json.loads(data.result)
    files = {
        'screenshot': os.path.join(os.getcwd(), 'web', 'static', 'results', 'screenshot', data_files['screenshot']),
        'json': os.path.join(os.getcwd(), 'web', 'static', 'results', 'json', data_files['json']),
        'js': os.path.join(os.getcwd(), 'web', 'static', 'results', 'js', data_files['js']),
        'html': os.path.join(os.getcwd(), 'web', 'static', 'results', 'html', data_files['html']),
    }

    for f in files:
        if os.path.exists(files[f]):
            os.remove(files[f])

    db.session.delete(data)
    db.session.commit()  

    return jsonify(True)

if __name__ == "__main__":
    # openedIntruo = False
    # if not openedIntruo:
    #     Intruo.action_open_browser('http://127.0.0.1:5000/')
    #     openedIntruo = True
    # app.run(debug=True, use_reloader=False)
    app.run(debug=True, use_reloader=True)