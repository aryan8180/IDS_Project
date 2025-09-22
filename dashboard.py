#!/usr/bin/env python3
from flask import Flask, render_template_string
import sqlite3

DB_FILE = "alerts.db"
app = Flask(__name__)

TEMPLATE = """
<!doctype html>
<title>IDS Alerts</title>
<h2>Recent Alerts</h2>
<table border=1 cellpadding=6>
<tr><th>ID</th><th>Time</th><th>Src</th><th>Dst</th><th>Proto</th><th>pkts</th><th>bytes</th><th>duration</th><th>score</th><th>severity</th></tr>
{% for r in rows %}
<tr style="background:{% if r[8]=='HIGH' %}#ffcccc{% elif r[8]=='MEDIUM' %}#fff2cc{% else %}#e8ffe8{% endif %}">
<td>{{r[0]}}</td><td>{{r[1]}}</td><td>{{r[2]}}</td><td>{{r[3]}}</td><td>{{r[4]}}</td><td>{{r[5]}}</td><td>{{r[6]}}</td><td>{{r[7]}}</td><td>{{'%.4f'|format(r[8] if r[8] is number else 0)}}</td><td>{{r[9]}}</td>
</tr>
{% endfor %}
</table>
<p>Auto-refresh every 5s.</p>
<script>setTimeout(()=>location.reload(),5000);</script>
"""

@app.route("/")
def index():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT id,ts,src_ip,dst_ip,proto,pkt_count,byte_count,duration,score,severity FROM alerts ORDER BY id DESC LIMIT 100")
    rows = cur.fetchall()
    conn.close()
    return render_template_string(TEMPLATE, rows=rows)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
