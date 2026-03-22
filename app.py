"""PassAudit Pro v2 - Flask App"""
import os, sys, io, json, traceback
from datetime import datetime
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from flask import Flask, render_template, request, jsonify, send_file
app = Flask(__name__)
app.config['SECRET_KEY'] = 'passaudit-pro-v2-2024'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditor_core_v2 import PasswordAnalyzer, HashDetector, BreachChecker, WordlistGenerator, BulkAuditor, PDFCracker
print("[OK] PassAudit Pro v2 Core loaded!")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json(force=True)
        pwd = data.get('password','')
        if not pwd: return jsonify({'error':'Password required'}), 400
        result = PasswordAnalyzer.analyze(pwd)
        if data.get('check_breach'):
            result['breach'] = BreachChecker.check(pwd)
        return jsonify({'success':True,'result':result})
    except Exception as e:
        return jsonify({'error':str(e)}), 500

@app.route('/api/detect-hash', methods=['POST'])
def detect_hash():
    try:
        data = request.get_json(force=True)
        h = data.get('hash','').strip()
        if not h: return jsonify({'error':'Hash required'}), 400
        types = HashDetector.detect(h)
        return jsonify({'success':True,'types':types,'hash':h})
    except Exception as e:
        return jsonify({'error':str(e)}), 500

@app.route('/api/crack-hash', methods=['POST'])
def crack_hash():
    try:
        data = request.get_json(force=True)
        h = data.get('hash','').strip()
        ht = data.get('hash_type','MD5')
        custom = data.get('wordlist',[])
        if not h: return jsonify({'error':'Hash required'}), 400
        # Build wordlist
        if custom:
            wl = custom if isinstance(custom,list) else [w for w in custom.split('\n') if w.strip()]
        else:
            from auditor_core_v2 import COMMON_PASSWORDS
            wl = COMMON_PASSWORDS + [
                'password','pass123','admin123','letmein','qwerty123',
                'Password1','Password@1','Admin@123','Welcome1','Test@123',
                'P@ssw0rd','P@ss123','Passw0rd!','Admin!23','Root@123',
            ]
        result = HashDetector.crack(h, ht, wl)
        return jsonify({'success':True,'result':result})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error':str(e)}), 500

@app.route('/api/breach-check', methods=['POST'])
def breach_check():
    try:
        data = request.get_json(force=True)
        pwd = data.get('password','')
        if not pwd: return jsonify({'error':'Password required'}), 400
        result = BreachChecker.check(pwd)
        return jsonify({'success':True,'result':result})
    except Exception as e:
        return jsonify({'error':str(e)}), 500

@app.route('/api/generate-wordlist', methods=['POST'])
def generate_wordlist():
    try:
        data = request.get_json(force=True)
        kw = data.get('keywords',[])
        if isinstance(kw,str): kw = [k.strip() for k in kw.split(',') if k.strip()]
        wl = WordlistGenerator.generate(
            name=data.get('name',''), dob=data.get('dob',''),
            keywords=kw, company=data.get('company',''),
            phone=data.get('phone',''), email=data.get('email',''),
            pet=data.get('pet',''), city=data.get('city',''),
            max_words=int(data.get('max_words',1000)),
        )
        return jsonify({'success':True,'wordlist':wl,'count':len(wl)})
    except Exception as e:
        return jsonify({'error':str(e)}), 500

@app.route('/api/crack-hash-file', methods=['POST'])
def crack_hash_file():
    try:
        h = request.form.get('hash','').strip()
        ht = request.form.get('hash_type','MD5')
        wordlist = []
        if 'wordlist_file' in request.files:
            f = request.files['wordlist_file']
            content = f.read().decode('utf-8','ignore')
            wordlist = [w.strip() for w in content.split('\n') if w.strip()]
        manual = request.form.get('manual_wordlist','')
        if manual:
            wordlist += [w.strip() for w in manual.split('\n') if w.strip()]
        if not wordlist:
            from auditor_core_v2 import COMMON_PASSWORDS
            wordlist = COMMON_PASSWORDS
        if not h: return jsonify({'error':'Hash required'}), 400
        result = HashDetector.crack(h, ht, wordlist)
        return jsonify({'success':True,'result':result})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error':str(e)}), 500

@app.route('/api/crack-pdf', methods=['POST'])
def crack_pdf():
    try:
        if 'pdf_file' not in request.files:
            return jsonify({'error':'PDF file required'}), 400
        pdf_file = request.files['pdf_file']
        pdf_bytes = pdf_file.read()
        wordlist = []
        if 'wordlist_file' in request.files:
            wf = request.files['wordlist_file']
            content = wf.read().decode('utf-8','ignore')
            wordlist = [w.strip() for w in content.split('\n') if w.strip()]
        manual = request.form.get('manual_wordlist','')
        if manual:
            wordlist += [w.strip() for w in manual.split('\n') if w.strip()]
        if not wordlist:
            from auditor_core_v2 import COMMON_PASSWORDS
            wordlist = COMMON_PASSWORDS + ['pdf123','document','secure','admin','password123']
        result = PDFCracker.crack(pdf_bytes, wordlist)
        return jsonify({'success':True,'result':result})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error':str(e)}), 500

@app.route('/api/bulk-audit', methods=['POST'])
def bulk_audit():
    try:
        data = request.get_json(force=True)
        pwds = data.get('passwords',[])
        if isinstance(pwds,str): pwds = [p for p in pwds.split('\n') if p.strip()]
        if not pwds: return jsonify({'error':'No passwords'}), 400
        result = BulkAuditor.audit(pwds[:100])
        return jsonify({'success':True,'result':result})
    except Exception as e:
        return jsonify({'error':str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT',5001))
    print(f"\n[*] PassAudit Pro v2 -> http://localhost:{port}\n")
    app.run(host='0.0.0.0', port=port, debug=False)
