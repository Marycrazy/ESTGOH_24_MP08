# Ações de Remediação para Vulnerabilidades de Segurança

## 1. Vulnerabilidades Identificadas e Soluções

### SQL Injection
**Problema**:
- Consultas SQL utilizavam strings concatenadas diretamente com entradas do utilizador.
- Isso permite que um atacante injete comandos SQL maliciosos, comprometendo a integridade e confidencialidade da base de dados.

**Solução**:
- Utilização de instruções parametrizadas com ?, fornecidas pela biblioteca SQLite, para evitar injeções SQL.
```python
# Antes
topic = conn.execute(f"SELECT * FROM topics WHERE id={topic_id}").fetchone()
comments = conn.execute(f"SELECT * FROM comments WHERE topic_id={topic_id}").fetchall()

# Depois
topic = conn.execute("SELECT * FROM topics WHERE id = ?", (topic_id,)).fetchone()
comments = conn.execute("SELECT * FROM comments WHERE topic_id = ?", (topic_id,)).fetchall()

```

### Exposição de Informações Sensíveis
**Problema**:
- Senhas dos utilizadores eram armazenadas em texto simples na base de dados, expondo os dados a um risco elevado caso a base de dados fosse comprometida.
**Soluções**:
- Implementação de hashing das senhas usando bcrypt antes de armazená-las.
```python
#antes
conn.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')")

#depois
hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
```

### Controlo de Acesso Inadequado
**Problema**:
- Qualquer utilizador, autenticado ou não, podia aceder e modificar recursos críticos, como tópicos e comentários, mesmo que não fosse o autor.

**Solução**:
- Implementação de verificações de controle de acesso, garantindo que apenas o autor do recurso possa modificá-lo ou excluí-lo.
```python
#antes
@app.route('/edit_topic/<int:topic_id>', methods=['GET', 'POST'])
def edit_topic(topic_id):
    conn = sqlite3.connect('database.db')
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        conn.execute(f"UPDATE topics SET title='{title}', content='{content}' WHERE id={topic_id}")
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
#depois
@app.route('/edit_topic/<int:topic_id>', methods=['GET', 'POST'])
def edit_topic(topic_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        author = session['username']
        topic = conn.execute('SELECT * FROM topics WHERE id = ? AND author = ?', (topic_id, author)).fetchone()
        if not topic:
            return "Permissão negada", 403
        conn.execute('UPDATE topics SET title = ?, content = ? WHERE id = ?', (title, content, topic_id))
        conn.commit()
        return redirect(url_for('index'))
```

### Sessões Inseguras
**Problema**:
- A chave secreta utilizada para as sessões era uma string estática e previsível ('123456'), facilitando ataques de força bruta ou predição.

**Solução**:
- Substituir a chave secreta por uma gerada dinamicamente usando os.urandom.
```python
#antes
app.secret_key = '123456'

#depois
import os
app.secret_key = os.urandom(24)
```


### Cross-Site Scripting (XSS)
**Problema**:
- Entradas do utilizador não eram sanitizadas antes de serem exibidas nos templates HTML, permitindo que scripts maliciosos fossem injetados.

**Solução**:
- Garantir a sanitização automática de entradas utilizando os recursos nativos de templating do Jinja2 (exibição com `{{ }}`).
```python
#antes
<td>{{ topic[1] }}</td>
<td>{{ topic[2] }}</td>
#depois
<td>{{ topic[1] | e }}</td>
<td>{{ topic[2] | e }}</td>
```

### CSRF Protection Desativada
**Problema**:
- Por padrão, o Flask não implementa proteção contra CSRF (Cross-Site Request Forgery). Isso pode permitir que um atacante envie requisições maliciosas em nome de um usuário autenticado.

**Solução**
- Adicionar proteção contra CSRF utilizando o Flask-WTF, que adiciona tokens CSRF aos formulários.
```python
#antes
from flask import Flask, request, render_template, redirect, url_for, session
app = Flask(__name__)

#depois
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)
```

