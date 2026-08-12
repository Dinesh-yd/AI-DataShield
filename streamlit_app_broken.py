from pathlib import Path
import re

src = Path('/mnt/data/streamlit_app.py')
text = src.read_text(encoding='utf-8')

# Remove any accidental /mnt or zip extraction code if present
patterns = [
    r'from pathlib import Path.*?extractall\(extract_dir\)\n',
]
for p in patterns:
    text = re.sub(p, '', text, flags=re.S)

# Safe UI upgrades only
text = text.replace(
    'st.set_page_config(page_title="PII Redaction & Breach Pipeline", layout="wide")',
    '''st.set_page_config(
    page_title="AI DataShield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)'''
)

if 'CYBER_CSS' not in text:
    text = text.replace(
        'TOTAL_PII_TYPES = 8',
        '''TOTAL_PII_TYPES = 8

CYBER_CSS = """
<style>
.stApp {background-color:#0B0F19;}
.main-title{
 text-align:center;
 font-size:48px;
 font-weight:900;
 color:#00E5FF;
}
.sub-title{
 text-align:center;
 color:#9CA3AF;
 margin-bottom:20px;
}
[data-testid="stMetric"]{
 border:1px solid #00E5FF55;
 border-radius:16px;
 padding:10px;
}
[data-testid="stMetric"]:hover{
 border:1px solid #00E5FF;
}
</style>
"""
'''
    )

out = Path('/mnt/data/CLEAN_streamlit_app.py')
out.write_text(text, encoding='utf-8')
print(out)
