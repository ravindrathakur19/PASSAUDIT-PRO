"""
PassAudit Pro v2 - Core Engine
"""
import hashlib, math, re, time, os, json, string
import requests
from datetime import datetime

COMMON_PASSWORDS = [
    "password","123456","password123","admin","letmein","qwerty","abc123",
    "monkey","1234567890","dragon","master","sunshine","princess","welcome",
    "shadow","superman","michael","football","batman","trustno1","iloveyou",
    "pass123","test123","hello123","admin123","root","pass","login","user",
    "password1","password12","123456789","12345678","12345","1234","123",
]

HASH_PATTERNS = {
    'MD5':    (r'^[a-f0-9]{32}$', 32),
    'SHA1':   (r'^[a-f0-9]{40}$', 40),
    'SHA256': (r'^[a-f0-9]{64}$', 64),
    'SHA512': (r'^[a-f0-9]{128}$', 128),
    'NTLM':   (r'^[A-Fa-f0-9]{32}$', 32),
    'bcrypt': (r'^\$2[aby]\$\d{2}\$', None),
}

# -- Password Strength -------------------------------------
class PasswordAnalyzer:
    @staticmethod
    def calculate_entropy(password):
        charset = 0
        if re.search(r'[a-z]', password): charset += 26
        if re.search(r'[A-Z]', password): charset += 26
        if re.search(r'[0-9]', password): charset += 10
        if re.search(r'[^a-zA-Z0-9]', password): charset += 32
        return round(len(password) * math.log2(charset), 2) if charset else 0

    @staticmethod
    def estimate_crack_time(entropy):
        if entropy <= 0: return 'Instantly'
        secs = (2 ** entropy) / 10_000_000_000
        if secs < 1: return 'Less than 1 second'
        elif secs < 60: return f'{int(secs)} seconds'
        elif secs < 3600: return f'{int(secs/60)} minutes'
        elif secs < 86400: return f'{int(secs/3600)} hours'
        elif secs < 2592000: return f'{int(secs/86400)} days'
        elif secs < 31536000: return f'{int(secs/2592000)} months'
        elif secs < 3153600000: return f'{int(secs/31536000)} years'
        else: return f'{int(secs/31536000):,} years'

    @classmethod
    def analyze(cls, password):
        if not password: return {'error': 'Empty password'}
        length = len(password)
        entropy = cls.calculate_entropy(password)
        has_lower  = bool(re.search(r'[a-z]', password))
        has_upper  = bool(re.search(r'[A-Z]', password))
        has_digits = bool(re.search(r'[0-9]', password))
        has_special= bool(re.search(r'[^a-zA-Z0-9]', password))
        score = 0
        score += min(length * 4, 40)
        score += 10 if has_lower else 0
        score += 10 if has_upper else 0
        score += 10 if has_digits else 0
        score += 15 if has_special else 0
        score += min(entropy / 3, 15)
        issues, warnings, suggestions = [], [], []
        seqs = ['abcdefghijklmnopqrstuvwxyz','0123456789','qwertyuiop','asdfghjkl','zxcvbnm']
        for seq in seqs:
            for i in range(len(seq)-2):
                if seq[i:i+3] in password.lower():
                    issues.append(f'Sequential pattern: "{seq[i:i+3]}"'); break
        if re.search(r'(.)\1{2,}', password): issues.append('Repeated characters (e.g. "aaa")')
        if password.lower() in COMMON_PASSWORDS: issues.append('This is a commonly used password!')
        walks = ['qwerty','asdf','zxcv','1234','abcd']
        for w in walks:
            if w in password.lower(): warnings.append(f'Keyboard walk: "{w}"')
        score -= len(issues)*10; score -= len(warnings)*5
        score = max(0, min(100, round(score)))
        if length < 8: suggestions.append('Use at least 8 characters')
        if length < 12: suggestions.append('12+ characters recommended')
        if not has_upper: suggestions.append('Add uppercase letters (A-Z)')
        if not has_lower: suggestions.append('Add lowercase letters (a-z)')
        if not has_digits: suggestions.append('Add numbers (0-9)')
        if not has_special: suggestions.append('Add special characters (!@#$%)')
        if score >= 80: strength = 'STRONG'
        elif score >= 60: strength = 'GOOD'
        elif score >= 40: strength = 'FAIR'
        elif score >= 20: strength = 'WEAK'
        else: strength = 'VERY WEAK'
        return {
            'password': password, 'length': length, 'entropy': entropy,
            'score': score, 'strength': strength,
            'has_lower': has_lower, 'has_upper': has_upper,
            'has_digits': has_digits, 'has_special': has_special,
            'crack_time': cls.estimate_crack_time(entropy),
            'issues': issues, 'warnings': warnings, 'suggestions': suggestions,
            'is_common': password.lower() in COMMON_PASSWORDS,
        }

# -- Hash Detector & Cracker -------------------------------
class HashDetector:
    @staticmethod
    def detect(hash_str):
        hash_str = hash_str.strip()
        matches = []
        for algo, (pattern, length) in HASH_PATTERNS.items():
            if re.match(pattern, hash_str, re.IGNORECASE):
                if length is None or len(hash_str) == length:
                    matches.append(algo)
        return matches

    @staticmethod
    def crack(hash_str, hash_type, wordlist):
        hash_str = hash_str.strip().lower()
        attempts = 0
        start = time.time()
        hash_funcs = {
            'MD5': hashlib.md5, 'SHA1': hashlib.sha1,
            'SHA256': hashlib.sha256, 'SHA512': hashlib.sha512,
        }
        for word in wordlist:
            word = word.strip()
            if not word: continue
            attempts += 1
            try:
                if hash_type == 'NTLM':
                    h = hashlib.new('md4', word.encode('utf-16-le')).hexdigest()
                elif hash_type == 'bcrypt':
                    try:
                        import bcrypt
                        if bcrypt.checkpw(word.encode(), hash_str.encode()):
                            return {'cracked': True, 'password': word, 'attempts': attempts, 'time': round(time.time()-start,3)}
                    except Exception:
                        return {'cracked': False, 'error': 'Install bcrypt: pip install bcrypt', 'attempts': 0, 'time': 0}
                    continue
                elif hash_type in hash_funcs:
                    h = hash_funcs[hash_type](word.encode()).hexdigest()
                else:
                    return {'cracked': False, 'error': f'Unsupported: {hash_type}', 'attempts': 0, 'time': 0}
                if h == hash_str:
                    return {'cracked': True, 'password': word, 'attempts': attempts, 'time': round(time.time()-start,3), 'hash_type': hash_type}
            except Exception:
                continue
        return {'cracked': False, 'attempts': attempts, 'time': round(time.time()-start,3), 'hash_type': hash_type}

# -- Breach Checker ----------------------------------------
class BreachChecker:
    @staticmethod
    def check(password):
        try:
            sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            resp = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}',
                                headers={'Add-Padding': 'true'}, timeout=5)
            if resp.status_code != 200:
                return {'checked': False, 'error': f'API error {resp.status_code}'}
            for line in resp.text.splitlines():
                parts = line.split(':')
                if len(parts) == 2 and parts[0] == suffix:
                    count = int(parts[1])
                    return {'checked': True, 'breached': True, 'count': count}
            return {'checked': True, 'breached': False, 'count': 0}
        except requests.exceptions.ConnectionError:
            return {'checked': False, 'error': 'No internet'}
        except Exception as e:
            return {'checked': False, 'error': str(e)}

# -- Wordlist Generator (Smart Human Patterns) -------------
class WordlistGenerator:

    # Common special char patterns people use
    SPECIALS = ['@','#','$','!','@#','!@','#$','@123','!123','@1','#1','$1']
    # Number patterns people add
    NUMBERS  = ['1','2','12','21','123','1234','12345','0','01','007',
                 '786','99','100','111','000','69','88','2024','2023',
                 '2022','2021','2020','2019','9','8','7','6','5','4','3']
    # Years range
    YEARS    = [str(y) for y in range(1970, 2025)]

    @classmethod
    def _leet(cls, word):
        t = {'a':'4','e':'3','i':'1','o':'0','s':'5','t':'7','g':'9','b':'8','l':'1'}
        r = word.lower()
        for ch, num in t.items():
            r = r.replace(ch, num)
        return r

    @classmethod
    def _name_parts(cls, name):
        """Split name into meaningful parts"""
        parts = name.strip().split()
        result = []
        for p in parts:
            p = p.strip()
            if not p: continue
            result.extend([p, p.lower(), p.capitalize(), p.upper()])
            if len(p) > 3:
                result.extend([p[:3], p[:4], p[:5], p.lower()[:3], p.lower()[:4]])
        # Full name combos
        if len(parts) >= 2:
            f, l = parts[0], parts[-1]
            result.extend([
                f"{f}{l}", f"{f.lower()}{l.lower()}",
                f"{f.capitalize()}{l.capitalize()}",
                f"{f[0]}{l}", f"{f[0].lower()}{l.lower()}",
                f"{f}{l[0]}", f"{f.lower()}{l[0].lower()}",
                f"{f}.{l}", f"{f}_{l}",
                f"{f.lower()}.{l.lower()}",
            ])
        return list(set([r for r in result if r and len(r) >= 3]))

    @classmethod
    def generate(cls, name='', dob='', keywords=None, company='',
                 phone='', email='', pet='', city='', max_words=1000):
        if keywords is None: keywords = []
        wordlist = set()
        base = set()

        # Collect base words
        if name:
            for p in cls._name_parts(name): base.add(p)
        if company:
            c = company.strip()
            base.update([c, c.lower(), c.capitalize(), c.upper(),
                         c.replace(' ',''), c.replace(' ','_'), c[:4], c[:5], c[:6]])
        if pet:
            p = pet.strip()
            base.update([p, p.lower(), p.capitalize(), p.upper()])
        if city:
            ct = city.strip()
            base.update([ct, ct.lower(), ct.capitalize()])
        if email and '@' in email:
            u = email.split('@')[0]
            base.update([u, u.lower(), u.capitalize()])
        for kw in keywords:
            kw = kw.strip()
            if kw: base.update([kw, kw.lower(), kw.capitalize(), kw.upper()])

        # DOB parts
        dob_parts = []
        if dob:
            clean = re.sub(r'[^0-9]', '', dob)
            if len(clean) >= 4:
                dob_parts = list(set(filter(None, [
                    clean, clean[-4:], clean[-2:], clean[:2],
                    clean[:4], clean[2:6] if len(clean)>=6 else '',
                    clean[:6] if len(clean)>=6 else '',
                    clean[4:] if len(clean)>=6 else '',
                ])))

        # Phone parts
        phone_parts = []
        if phone:
            ph = re.sub(r'[^0-9]', '', phone)
            phone_parts = list(set(filter(None,[ph,ph[-4:],ph[-6:],ph[:4],ph[-10:]])))

        # -- MAIN GENERATION -------------------------------
        for word in base:
            if not word or len(word) < 2: continue

            # 1. Plain word
            wordlist.add(word)
            wordlist.add(word.lower())
            wordlist.add(word.capitalize())

            # 2. word + number (most common human pattern)
            for n in cls.NUMBERS:
                wordlist.add(f"{word.capitalize()}{n}")
                wordlist.add(f"{word.lower()}{n}")
                wordlist.add(f"{n}{word.capitalize()}")

            # 3. word + special char (Chandan@, Chandan#)
            for sp in cls.SPECIALS:
                wordlist.add(f"{word.capitalize()}{sp}")
                wordlist.add(f"{word.lower()}{sp}")

            # 4. word + special + number (Chandan@123, Chandan#1)
            for sp in ['@','#','$','!']:
                for n in ['1','12','123','1234','2024','2023','786','99','0']:
                    wordlist.add(f"{word.capitalize()}{sp}{n}")
                    wordlist.add(f"{word.lower()}{sp}{n}")

            # 5. word + number + special (Chandan123!)
            for n in ['1','12','123','1234']:
                for sp in ['!','@','#','$']:
                    wordlist.add(f"{word.capitalize()}{n}{sp}")

            # 6. word + year (Chandan2024, Chandan1995)
            for yr in cls.YEARS[-15:]:  # last 15 years
                wordlist.add(f"{word.capitalize()}{yr}")
                wordlist.add(f"{word.lower()}{yr}")
                wordlist.add(f"{word.capitalize()}{yr}!")
                wordlist.add(f"{word.capitalize()}{yr}@")

            # 7. Leet speak
            leet = cls._leet(word)
            if leet != word.lower():
                wordlist.add(leet)
                wordlist.add(f"{leet}123")
                wordlist.add(f"{leet}@123")
                wordlist.add(f"{leet}!")

            # 8. DOB combinations
            for dp in dob_parts:
                wordlist.add(f"{word.capitalize()}{dp}")
                wordlist.add(f"{word.lower()}{dp}")
                wordlist.add(f"{dp}{word.capitalize()}")
                wordlist.add(f"{word.capitalize()}{dp}!")
                wordlist.add(f"{word.capitalize()}{dp}@")
                wordlist.add(f"{word.capitalize()}{dp}#")

            # 9. Phone combinations
            for ph in phone_parts:
                wordlist.add(f"{word.capitalize()}{ph}")
                wordlist.add(f"{word.lower()}{ph}")

            # 10. word + 098, 123, 456 etc (Chandan@098 like your example)
            for combo in ['@098','@456','@789','@000','#098','@321','@111','@007',
                          '@123#','@123!','!@#','@2024','#2024','$123','!123#']:
                wordlist.add(f"{word.capitalize()}{combo}")
                wordlist.add(f"{word.lower()}{combo}")

            # 11. CAPITAL word patterns
            wordlist.add(f"{word.upper()}123")
            wordlist.add(f"{word.upper()}@123")
            wordlist.add(f"{word.upper()}!")

        # Two-word combinations
        base_list = [w for w in base if w and 3 <= len(w) <= 8]
        for i, w1 in enumerate(base_list[:10]):
            for w2 in base_list[i+1:i+6]:
                if w1 == w2: continue
                wordlist.add(f"{w1.capitalize()}{w2.capitalize()}")
                wordlist.add(f"{w1.capitalize()}{w2.capitalize()}1")
                wordlist.add(f"{w1.capitalize()}{w2.capitalize()}123")
                wordlist.add(f"{w1.capitalize()}{w2.capitalize()}@")
                wordlist.add(f"{w1.lower()}{w2.lower()}123")

        # Filter: 6-16 chars (real password length range)
        wordlist = {w for w in wordlist if w and 6 <= len(w) <= 16}
        # Smart sort: Most realistic passwords first
        # Full base words get priority over truncated ones
        full_words = {w.lower() for w in base if len(w) >= 5}
        
        def sort_key(w):
            if not w: return (99, 99, w)
            starts_cap = w[0].isupper()
            has_special = any(c in w for c in '@#$!')
            has_digit = any(c.isdigit() for c in w)
            length_ok = 8 <= len(w) <= 13
            # Check if starts with a full recognizable word
            is_full_word = any(w.lower().startswith(fw) for fw in full_words)
            if starts_cap and is_full_word and has_digit and has_special and length_ok: p = 0
            elif starts_cap and is_full_word and has_digit and has_special: p = 1
            elif starts_cap and is_full_word and has_digit and length_ok: p = 2
            elif starts_cap and is_full_word and has_digit: p = 3
            elif starts_cap and is_full_word and has_special: p = 4
            elif starts_cap and is_full_word: p = 5
            elif starts_cap and has_digit and has_special: p = 6
            elif starts_cap and has_digit: p = 7
            elif starts_cap: p = 8
            elif has_digit and has_special: p = 9
            else: p = 10
            return (p, abs(len(w)-10), w)
        result = sorted(list(wordlist), key=sort_key)[:max_words]
        return result


# -- PDF Password Cracker ----------------------------------
class PDFCracker:
    @staticmethod
    def crack(pdf_bytes, wordlist, progress_callback=None):
        try:
            import pikepdf
        except ImportError:
            return {'success': False, 'error': 'Install pikepdf: pip install pikepdf'}

        import io
        attempts = 0
        start = time.time()
        total = len(wordlist)

        for i, password in enumerate(wordlist):
            password = password.strip()
            if not password: continue
            attempts += 1
            try:
                pikepdf.open(io.BytesIO(pdf_bytes), password=password)
                elapsed = round(time.time() - start, 2)
                return {
                    'success': True, 'cracked': True,
                    'password': password, 'attempts': attempts,
                    'time': elapsed
                }
            except pikepdf.PasswordError:
                if progress_callback and attempts % 100 == 0:
                    progress_callback(attempts, total)
                continue
            except Exception as e:
                return {'success': False, 'error': str(e)}

        elapsed = round(time.time() - start, 2)
        return {
            'success': True, 'cracked': False,
            'attempts': attempts, 'time': elapsed,
            'message': f'Password not found in {attempts} attempts'
        }


# -- Bulk Auditor ------------------------------------------
class BulkAuditor:
    @staticmethod
    def audit(passwords):
        results = []
        for pwd in passwords:
            pwd = pwd.strip()
            if not pwd: continue
            results.append(PasswordAnalyzer.analyze(pwd))
        total = len(results)
        sc = {'STRONG':0,'GOOD':0,'FAIR':0,'WEAK':0,'VERY WEAK':0}
        for r in results: sc[r['strength']] = sc.get(r['strength'],0)+1
        avg = round(sum(r['score'] for r in results)/total,1) if total else 0
        return {
            'total': total, 'results': results,
            'summary': {
                'avg_score': avg,
                'strength_counts': sc,
                'common_count': sum(1 for r in results if r['is_common']),
                'strong_pct': round(sc['STRONG']/total*100,1) if total else 0,
                'weak_pct': round((sc['WEAK']+sc['VERY WEAK'])/total*100,1) if total else 0,
            }
        }
