"""Europlátano: importador controlado de hallazgos de auditoría a solicitudes Fracttal.
Sin borrados, sin crear órdenes de trabajo. No conserva ficheros entre sesiones.
"""
from __future__ import annotations
import hashlib, hmac, io, re, unicodedata, zipfile, os
from collections import Counter
from datetime import datetime, date, timezone
from zoneinfo import ZoneInfo
import requests
import pandas as pd
import streamlit as st

API = 'https://app.fracttal.com/api'
TOKEN_URL = 'https://one.fracttal.com/oauth/token'
APP_VER = '1.6'
st.set_page_config(page_title='Calidad → Fracttal | Europlátano', page_icon='📋', layout='wide')
st.title('📋 Auditorías de Calidad → Solicitudes Fracttal')
st.caption(f'Europlátano · V{APP_VER} · Diagnóstico HTTP · IFS / GLOBALG.A.P. · No crea órdenes de trabajo')

def sec(k):
    try: return str(st.secrets.get(k,'')).strip()
    except Exception: return ''

pw=sec('APP_PASSWORD')
if not pw:
    st.error('Falta APP_PASSWORD en Streamlit → Settings → Secrets.'); st.stop()
if not st.session_state.get('quality_login'):
    with st.form('access'):
        password=st.text_input('Contraseña de acceso', type='password')
        entered=st.form_submit_button('Entrar')
    if entered:
        if hmac.compare_digest(password,pw): st.session_state.quality_login=True; st.rerun()
        else: st.error('Contraseña incorrecta')
    st.stop()
with st.sidebar:
    if st.button('Cerrar sesión'): st.session_state.quality_login=False; st.rerun()
    st.info('No subas credenciales ni el Excel a un repositorio público. Las solicitudes son reales si confirmas el envío.')

CID=sec('FRACTTAL_CLIENT_ID'); CSECRET=sec('FRACTTAL_CLIENT_SECRET')

def norm(v):
    s=unicodedata.normalize('NFKD',str(v or ''))
    return ''.join(c for c in s if not unicodedata.combining(c)).strip().lower()

def dtstr(v):
    if isinstance(v,(datetime,date)): return v.strftime('%Y-%m-%d')
    if pd.isna(v):return ''
    q=pd.to_datetime(v,errors='coerce',dayfirst=True)
    return q.strftime('%Y-%m-%d') if not pd.isna(q) else ''

def clean(v):
    if v is None or pd.isna(v): return ''
    return str(v).strip()

def ident(date_val, area, incidence, occurrence, plant_code):
    # Referencia estable entre exportaciones aun si cambian el orden de filas.
    seed='|'.join((dtstr(date_val),norm(area),norm(incidence),str(occurrence)))
    return 'CAL-IFS-'+plant_code+'-'+hashlib.sha256(seed.encode('utf-8')).hexdigest()[:16].upper()

def extract(blob, plant_code):
    frame=pd.read_excel(io.BytesIO(blob),sheet_name=0,header=1,engine='openpyxl',dtype=object)
    if frame.shape[1]<10: raise ValueError('El Excel no contiene las diez columnas esperadas de Calidad.')
    result=[]; occurred=Counter()
    for ix,raw in frame.iterrows():
        row=list(raw.values)
        incident=clean(row[3]); area=clean(row[2]); status=clean(row[9]); dept=clean(row[6]); day=dtstr(row[1])
        if not incident or not day: continue
        signature=(day,norm(area),norm(incident));occurred[signature]+=1
        ref=ident(row[1],area,incident,occurred[signature],plant_code)
        maintenance='mantenimiento' in norm(dept)
        opened=norm(status) in ('abierta','abierto','pendiente')
        result.append(dict(fila_excel=int(ix)+3,referencia=ref,fecha=day,zona=area,
          incidencia=incident,accion_calidad=clean(row[4]),evidencia=clean(row[5]),
          responsable=dept,fecha_prevista=dtstr(row[7]),fecha_cierre=dtstr(row[8]),
          estado=status,observaciones=clean(row[10]) if len(row)>10 else '',
          seleccion=bool(opened and maintenance),revision=('Seleccionada' if opened and maintenance else 'No seleccionada')))
    return pd.DataFrame(result)

def oauth():
    if not CID or not CSECRET: raise RuntimeError('Faltan FRACTTAL_CLIENT_ID y FRACTTAL_CLIENT_SECRET en Secrets.')
    res=requests.post(TOKEN_URL,auth=(CID,CSECRET),data={'grant_type':'client_credentials'},timeout=25)
    if res.status_code!=200: raise RuntimeError('Autenticación OAuth rechazada (HTTP %s).' % res.status_code)
    body=res.json();token=body.get('access_token')
    if not token:raise RuntimeError('Fracttal no devolvió token OAuth.')
    return token

def _safe_api_error(body):
    """Muestra detalles de validación sin volcar tokens ni cuerpos de solicitudes."""
    if not isinstance(body,dict):
        return 'Fracttal no devolvió un error JSON interpretable.'
    parts=[]
    for key in ('message','error','error_description','detail','errors'):
        value=body.get(key)
        if not value: continue
        if isinstance(value,dict):
            for field,reason in list(value.items())[:12]:
                parts.append(f'{field}: {reason}')
        elif isinstance(value,list):
            for entry in value[:12]:
                if isinstance(entry,dict):
                    parts.append(f"{entry.get('field',entry.get('property','campo'))}: {entry.get('message',entry.get('error','validación incorrecta'))}")
                else: parts.append(str(entry))
        else: parts.append(str(value))
    msg=' | '.join(parts) if parts else 'Sin detalle de validación en la respuesta.'
    # No mostrar accidentalmente credenciales ni datos completos de la solicitud.
    for secret in (CID,CSECRET):
        if secret: msg=msg.replace(secret,'[OCULTO]')
    msg=re.sub(r'(?i)(bearer\s+)[A-Za-z0-9._-]+',r'\1[OCULTO]',msg)
    return msg[:1200]

def request(method,endpoint,token,*,payload=None,params=None):
    headers={'Authorization':'Bearer '+token,'Accept':'application/json'}
    if payload is not None: headers['Content-Type']='application/json'
    res=requests.request(method,API+endpoint,headers=headers,json=payload,params=params,timeout=40)
    try: body=res.json()
    except ValueError: body={}
    if res.status_code>=400 or (isinstance(body,dict) and body.get('success') is False):
        raise RuntimeError(f'{method} {endpoint}: HTTP {res.status_code}. {_safe_api_error(body)}')
    return body

def fetch_all(token):
    """Recorre todas las páginas usando start/limit oficiales de Fracttal.

    Ante inconsistencias, se interrumpe sin habilitar ninguna escritura.
    """
    page_size = 100
    since = '2023-01-01T00:00:00-00'
    until = datetime.now(timezone.utc).strftime('%Y-%m-%dT23:59:59-00')
    found = []
    seen_codes = set()
    expected_total = None
    for start in range(0, 100000, page_size):
        params = {'since': since, 'until': until, 'start': start, 'limit': page_size}
        data = request('GET', '/work_requests/', token, params=params)
        if not isinstance(data, dict) or not isinstance(data.get('data'), list):
            raise RuntimeError('Respuesta de Fracttal no verificable al consultar solicitudes.')
        batch = data['data']
        try:
            total = int(data['total'])
        except (KeyError, ValueError, TypeError):
            raise RuntimeError('Fracttal no informó el total de solicitudes. Importación bloqueada.')
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise RuntimeError('El total de solicitudes cambió durante la paginación. Vuelve a consultar.')
        if len(batch) > page_size or start + len(batch) > expected_total:
            raise RuntimeError('Fracttal devolvió un bloque de tamaño incoherente. Importación bloqueada.')
        if not batch and len(found) < expected_total:
            raise RuntimeError('La paginación terminó antes de recuperar todas las solicitudes.')
        for item in batch:
            if not isinstance(item, dict) or item.get('id_code') is None:
                raise RuntimeError('Solicitud sin identificador único en la consulta. Importación bloqueada.')
            code = str(item['id_code'])
            if code in seen_codes:
                raise RuntimeError('Fracttal repitió solicitudes entre páginas. Importación bloqueada.')
            seen_codes.add(code)
            found.append(item)
        if len(found) == expected_total:
            break
        if len(batch) != page_size:
            raise RuntimeError('Página incompleta antes de llegar al total. Importación bloqueada.')
    else:
        raise RuntimeError('Se superó el límite de seguridad de paginación.')
    if len(found) != expected_total:
        raise RuntimeError(f'Consulta incompleta: {len(found)} de {expected_total}. Importación bloqueada.')
    # identifier es la referencia oficial. Como respaldo, se busca la referencia
    # también en las observaciones de solicitudes anteriores.
    refs = set()
    for item in found:
        identifier = str(item.get('identifier') or '').strip()
        if identifier:
            refs.add(identifier)
        observation = str(item.get('observation') or '')
        refs.update(re.findall(r'CAL-IFS-[A-Z]{3}-[0-9A-F]{16}', observation, re.IGNORECASE))
    return refs, len(found)

def title(row):
    text=re.sub(r'\s+',' ',str(row['incidencia'])).strip()
    return ('AUDITORÍA IFS · '+text)[:200]

def body_of(row,user_code,requested_by,urgent,plant_name,asset_code,group,category1,category2):
    parts=[f"Origen: inspección interna IFS · {plant_name}",f"Referencia: {row['referencia']}",f"Fecha de detección: {row['fecha']}",f"Zona/área: {row['zona']}",f"Hallazgo de Calidad: {row['incidencia']}"]
    for label,col in [('Acción correctiva indicada por Calidad','accion_calidad'),('Evidencia','evidencia'),('Responsable en Excel','responsable'),('Fecha objetivo de cierre','fecha_prevista'),('Observaciones','observaciones')]:
        val=str(row.get(col,'')).strip()
        if val: parts.append(f'{label}: {val}')
    return {'user_code':user_code,'user_type':'HUMAN_RESOURCES','description':title(row),
      'observation':'\n'.join(parts),'date_incident':row['fecha']+'T12:00:00-00',
      'requested_by':requested_by[:200], 'identifier':row['referencia'],'is_urgent':bool(urgent),
      'code':asset_code,'types_description':group,'types_1_description':category1,
      'types_2_description':category2}

MAX_ZIP_BYTES=180*1024*1024
MAX_IMAGE_BYTES=20*1024*1024
MAX_IMAGES=350
PHOTO_EXT={'.jpg','.jpeg','.png','.gif','.bmp','.tif','.tiff'}

def load_photos(blob):
    if len(blob)>MAX_ZIP_BYTES: raise ValueError('ZIP demasiado grande (máximo 180 MB).')
    images={}; total=0
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for entry in z.infolist():
            if entry.is_dir() or entry.filename.startswith('__MACOSX/') or os.path.basename(entry.filename).startswith('.'):
                continue
            name=entry.filename.replace('\\','/')
            if name.startswith('/') or '..' in name.split('/') or entry.flag_bits & 1:
                raise ValueError('ZIP con rutas no permitidas o archivos cifrados.')
            if os.path.splitext(name)[1].lower() not in PHOTO_EXT: continue
            if entry.file_size>MAX_IMAGE_BYTES: raise ValueError('Imagen demasiado grande: '+os.path.basename(name))
            if len(images)>=MAX_IMAGES: raise ValueError('Hay más de 350 fotografías.')
            total+=entry.file_size
            if total>MAX_ZIP_BYTES: raise ValueError('Las imágenes descomprimidas superan 180 MB.')
            content=z.read(entry)
            if not content: continue
            images[name]=content
    return images

def match_photos(images, df):
    rows=[]
    for path in images:
        stem=norm(os.path.splitext(os.path.basename(path))[0]); hits=[]
        for r in df.itertuples():
            ref=norm(r.referencia)
            # Referencia exacta o fila explícita; nunca adivinar por coincidencias parciales.
            if ref in stem or re.search(r'(?<!\d)(?:fila|registro|hallazgo)[ _-]*0*'+str(r.fila_excel)+r'(?!\d)',stem):
                hits.append(r.referencia)
            elif clean(r.evidencia) and len(norm(r.evidencia))>=6 and norm(r.evidencia) in stem:
                hits.append(r.referencia)
        hits=list(dict.fromkeys(hits))
        rows.append({'fotografia':path,'referencia':hits[0] if len(hits)==1 else '(Sin asignar)'})
    return pd.DataFrame(rows)

def upload_photo(token, filename, content):
    signed=request('POST','/s3_object/',token,payload={'name':os.path.basename(filename),'size':len(content)})
    d=signed.get('data') if isinstance(signed,dict) else None
    required=('host','key','acl','policy','credential','date','signature')
    if not isinstance(d,dict) or not all(d.get(x) for x in required):
        raise RuntimeError('Fracttal no devolvió las credenciales completas de subida.')
    fields=[('key',d['key']),('acl',d['acl']),('policy',d['policy']),('x-amz-credential',d['credential']),('x-amz-algorithm','AWS4-HMAC-SHA256'),('x-amz-date',d['date']),('x-amz-signature',d['signature']),('success_action_status','200')]
    host=d['host']
    if not host.startswith('https://'): raise RuntimeError('Destino de subida no seguro.')
    res=requests.post(host,data=fields,files={'file':(os.path.basename(filename),io.BytesIO(content))},timeout=90)
    if res.status_code not in (200,201,204): raise RuntimeError('No se pudo transferir la fotografía al almacenamiento (HTTP %s).' % res.status_code)
    return d['key']

def attach_photos(token, request_id, assigned, images):
    paths=[]
    for path in assigned:
        key=upload_photo(token,path,images[path])
        paths.append({'name':key,'description':'Evidencia de Calidad: '+os.path.basename(path)})
    if paths:
        request('POST',f'/work_requests_attachments_files/{int(request_id)}',token,payload={'id_status':1,'paths':paths})
    return len(paths)

def response_id(response):
    data=response.get('data') if isinstance(response,dict) else None
    if isinstance(data,list) and len(data)==1: data=data[0]
    if isinstance(data,dict):
        value=data.get('id_code',data.get('id'))
        if value is not None: return int(value)
    return None

PLANTS = {
    'Palomares': ('PAL','GEN-CAL-PAL'),
    'Puntallana': ('PUN','GEN-CAL-PUN'),
    'Tenerife Sur': ('TFS','GEN-CAL-TFS'),
    'Tenerife Norte': ('TFN','GEN-CAL-TFN'),
    'La Caleta': ('LCL','GEN-CAL-LCL'),
    'Puerto de la Cruz': ('PTC','GEN-CAL-PTC'),
    'El Hierro': ('HIE','GEN-CAL-HIE'),
}
st.subheader('0 · Centro de trabajo')
plant_name=st.selectbox('Planta a la que corresponden las incidencias',list(PLANTS),key='quality_plant')
plant_code,asset_code=PLANTS[plant_name]
st.info(f'Activo provisional de Fracttal: {asset_code} · Centro: {plant_name}')
upload=st.file_uploader('1 · Selecciona el Excel original del Departamento de Calidad',type=['xlsx'])
if upload is None:
    st.info('Sube el Excel de Inspecciones internas IFS de la planta seleccionada. Por defecto se seleccionarán únicamente las incidencias ABIERTAS asignadas a Mantenimiento, incluidas las compartidas.');st.stop()
blob=upload.getvalue()
try: df=extract(blob,plant_code)
except Exception as exc: st.error(f'No se pudo interpretar el Excel: {exc}');st.stop()
if df.empty:st.warning('No se encontraron registros válidos.');st.stop()
sc=norm('abierta')
open_count=sum(norm(x) in ('abierta','abierto','pendiente') for x in df.estado)
selected_default=int(df.seleccion.sum())
st.subheader('2 · Análisis del archivo')
a,b,c=st.columns(3);a.metric('Hallazgos con fecha',len(df));b.metric('Abiertos',open_count);c.metric('Abiertos de Mantenimiento',selected_default)
st.caption('La selección es automática, pero puedes desmarcar cualquier incidencia antes de importar. No se importan las cerradas por defecto.')
with st.expander('Revisar los hallazgos abiertos de otros departamentos'):
    other=df[(df.estado.map(norm).isin(('abierta','abierto','pendiente'))) & (~df.responsable.map(norm).str.contains('mantenimiento'))]
    st.dataframe(other[['fila_excel','zona','incidencia','responsable','estado']],hide_index=True,use_container_width=True)

st.subheader('3 · Selecciona qué solicitudes crear')
choices=['Solo abiertas de Mantenimiento (recomendado)','Todas las abiertas (revisión necesaria)','Mostrar todo el histórico']
mode=st.radio('Vista',choices,index=0,horizontal=False)
if mode==choices[0]:view=df[df.seleccion].copy()
elif mode==choices[1]:view=df[df.estado.map(norm).isin(('abierta','abierto','pendiente'))].copy()
else:view=df.copy()
# Selección masiva: restablece el editor al cambiar de vista o al pulsar los botones.
# La clave de revisión evita que Streamlit conserve marcas antiguas del data_editor.
selection_scope=f'{hashlib.sha256(blob).hexdigest()[:16]}_{choices.index(mode)}'
if st.session_state.get('quality_selection_scope')!=selection_scope:
    st.session_state['quality_selection_scope']=selection_scope
    st.session_state['quality_selection_revision']=0
    st.session_state['quality_selection_override']=None
left,right=st.columns(2)
with left:
    mark_all=st.button('☑️ Marcar todas las visibles',use_container_width=True,key='quality_mark_all')
with right:
    unmark_all=st.button('⬜ Desmarcar todas las visibles',use_container_width=True,key='quality_unmark_all')
if mark_all or unmark_all:
    st.session_state['quality_selection_override']=bool(mark_all)
    st.session_state['quality_selection_revision']+=1
if st.session_state['quality_selection_override'] is not None:
    view['seleccion']=st.session_state['quality_selection_override']
st.caption('Estos botones afectan solo a la vista actual. Después puedes marcar o desmarcar incidencias individualmente.')
cols=['seleccion','fila_excel','fecha','zona','incidencia','responsable','estado','referencia']
editor_key=f"quality_editor_{selection_scope}_{st.session_state['quality_selection_revision']}"
edited=st.data_editor(view[cols],hide_index=True,use_container_width=True,num_rows='fixed',key=editor_key,disabled=[c for c in cols if c!='seleccion'],column_config={'seleccion':st.column_config.CheckboxColumn('Importar'), 'incidencia':st.column_config.TextColumn('Hallazgo',width='large'),'zona':st.column_config.TextColumn('Zona',width='medium')})
selected_refs=set(edited.loc[edited['seleccion']==True,'referencia'].tolist())
selected=df[df.referencia.isin(selected_refs)].copy()
st.caption(f'Seleccionadas para revisión: {len(selected)}. Cada hallazgo conservará una referencia estable para evitar duplicados.')
if selected.empty:st.stop()

st.subheader('3B · Fotografías de las incidencias (opcional)')
photo_zip=st.file_uploader('Opción A · ZIP con fotografías de Calidad',type=['zip'],key='photos_zip')
gallery_files=st.file_uploader('Opción B · Selecciona fotos directamente desde la galería o Archivos (sin ZIP)',type=['jpg','jpeg','png','gif','bmp','tif','tiff'],accept_multiple_files=True,key='photos_gallery',help='En iPad, pulsa Browse files / Examinar archivos y selecciona Fototeca si Safari ofrece esa opción. También puedes elegir fotos guardadas en Archivos.')
images={}; photo_map={}; photo_error=False
try:
    if photo_zip is not None:
        images.update(load_photos(photo_zip.getvalue()))
    if gallery_files:
        if len(images)+len(gallery_files)>MAX_IMAGES:
            raise ValueError('Se supera el máximo de 350 fotografías.')
        total_bytes=sum(len(v) for v in images.values())
        for i,f in enumerate(gallery_files,1):
            content=f.getvalue()
            if len(content)>MAX_IMAGE_BYTES:
                raise ValueError('Imagen demasiado grande: '+f.name)
            total_bytes+=len(content)
            if total_bytes>MAX_ZIP_BYTES:
                raise ValueError('Las imágenes superan 180 MB en total.')
            # El prefijo identifica la carga de galería y evita colisiones con nombres del ZIP.
            name=f'Galeria/{i:03d}_{os.path.basename(f.name)}'
            images[name]=content
    if images:
        st.caption(f'{len(images)} fotografías encontradas. Selecciona la referencia de cada una; ninguna se envía sin asignar.')
        mapping=match_photos(images,df)
        options=['(Sin asignar)']+df['referencia'].tolist()
        fingerprint=hashlib.sha256(blob)
        for name,content in images.items():
            fingerprint.update(name.encode('utf-8'));fingerprint.update(hashlib.sha256(content).digest())
        editor_key='photo_map_'+fingerprint.hexdigest()[:14]
        mapping=st.data_editor(mapping,key=editor_key,hide_index=True,use_container_width=True,num_rows='fixed',disabled=['fotografia'],column_config={'referencia':st.column_config.SelectboxColumn('Incidencia / referencia',options=options,required=True),'fotografia':st.column_config.TextColumn('Archivo',width='large')})
        for r in mapping.itertuples():
            if r.referencia!='(Sin asignar)': photo_map.setdefault(r.referencia,[]).append(r.fotografia)
        linked=sum(len(v) for v in photo_map.values())
        st.info(f'Fotografías vinculadas: {linked} de {len(images)}. Sin vincular: {len(images)-linked}.')
        with st.expander('Vista previa de fotografías asociadas',expanded=bool(gallery_files)):
            for r in mapping.itertuples():
                if r.referencia!='(Sin asignar)':
                    st.write(f'{r.fotografia} → {r.referencia}')
                    if os.path.splitext(r.fotografia)[1].lower() in ('.jpg','.jpeg','.png','.gif'):
                        st.image(images[r.fotografia],width=260)
        selected_photo_count=sum(len(photo_map.get(ref,[])) for ref in selected_refs)
        st.caption(f'Fotografías que se intentarán adjuntar a las solicitudes seleccionadas: {selected_photo_count}.')
    elif photo_zip is not None:
        st.warning('El ZIP no contiene fotografías compatibles.')
except Exception as exc:
    st.error('No se pudieron preparar las fotografías: '+str(exc));photo_error=True
if photo_error: st.stop()

st.subheader('4 · Configuración de Fracttal')
def_user=sec('FRACTTAL_REQUEST_USER_CODE')
user_code=st.text_input('Código del usuario/recurso humano que registrará la solicitud (obligatorio)',value=def_user,help='Es user_code, NO el nombre ni el email. Lo puedes guardar en Secrets como FRACTTAL_REQUEST_USER_CODE.')
requested_by=st.text_input('Solicitante (obligatorio)',value='Departamento de Calidad – Europlátano')
urgency=st.selectbox('Urgencia por defecto', ['No urgente (recomendado)','Urgente (solo si procede)'])
st.caption('Cada solicitud se asociará al activo provisional de la planta. El grupo y las clasificaciones deben coincidir con los catálogos existentes en Fracttal.')
group=st.selectbox('Grupo Fracttal', ['Calidad / Ajuste / Especificación','Incidencia (sin paro)','Mejora / Solicitud (no avería)','Seguridad / Riesgo / Medioambiente','Avería (con paro)'],index=0)
cat1_options=['Infraestructura y edificio','Aire comprimido y neumática','Automatización y control (PLC, HMI, variadores, sensores','Electricidad potencia (cuadros, protecciones, motores)','Envasado / embolsado / sellado','Etiquetado / impresión','Frío industrial (cámaras/túnel)','Hidráulica / bombeo / fluidos','Lavado / agua de proceso / drenajes','Paletizado / flejado','Pesaje / control / detección','Transportadores y movimiento','Vehículos de transporte (carretera / recogida)','Vehículos industriales (carretillas, transpaletas, etc.)']
cat2_options=['Otros / no sé','Alarma / error','Atasco / bloqueo','Está roto','Falta elemento/ inexistente','Falta nivel / falta presión / falta suministro','Funciona pero mal','Hace ruido anormal','Huele mal / quemado / humo','No funciona / no arranca','Pierde líquido / fuga','Roto / partido','Se calienta','Se para / falla a ratos','Suelto / desajustado','Vibra']
category1=st.selectbox('Clasificación 1 (catálogo de Fracttal)',cat1_options)
category2=st.selectbox('Clasificación 2 (catálogo de Fracttal)',cat2_options)
st.warning('Revisa las clasificaciones antes de importar: estos valores se aplican a todas las incidencias seleccionadas. Para distintas clases, haz importaciones separadas.')
if not user_code.strip() or not requested_by.strip(): st.warning('Completa el código de usuario y el solicitante para continuar.');st.stop()

st.subheader('5 · Comprobar duplicados (solo lectura)')
filetag=hashlib.sha256(blob+plant_code.encode()).hexdigest()[:12]
if st.button('🔎 Consultar solicitudes existentes en Fracttal'):
    try:
        tk=oauth();refs,seen=fetch_all(tk)
        st.session_state['audit_check']={'tag':filetag,'refs':refs,'total':seen,'time':datetime.now().isoformat()}
        st.success(f'Consulta completada: {seen} solicitudes examinadas.')
    except Exception as e:
        st.session_state.pop('audit_check',None);st.error(str(e))
check=st.session_state.get('audit_check')
if not check or check.get('tag')!=filetag:
    st.warning('Primero debes consultar Fracttal. La importación permanece bloqueada.');st.stop()
existing=check['refs'];new=selected[~selected.referencia.isin(existing)]
duplicates=selected[selected.referencia.isin(existing)]
x,y=st.columns(2);x.metric('Pendientes de crear',len(new));y.metric('Ya existentes / omitidas',len(duplicates))
if not duplicates.empty:
    with st.expander('Ver solicitudes ya registradas'):
        st.dataframe(duplicates[['referencia','zona','incidencia']],hide_index=True)
if new.empty:
    st.success('No hay nuevas solicitudes que crear.');st.stop()
with st.expander('Vista previa: datos que se enviarán a Fracttal'):
    st.dataframe(new[['referencia','fecha','zona','incidencia','accion_calidad']],hide_index=True,use_container_width=True)

st.subheader('6 · Crear solicitudes')
st.warning('Esta acción CREA solicitudes REALES de trabajo. Para la primera puesta en marcha, elige «Una sola solicitud de prueba».')
run_mode=st.radio('Alcance de la importación',['Una sola solicitud de prueba','Todas las seleccionadas que falten'],horizontal=False)
if run_mode=='Una sola solicitud de prueba':
    opts=[f"Fila {int(r.fila_excel)} · {str(r.zona)[:35]} · {str(r.incidencia)[:85]}" for r in new.itertuples()]
    chosen=st.selectbox('Incidencia de prueba',opts)
    target=new.iloc[[opts.index(chosen)]]
else:target=new
confirmed=st.checkbox('He comprobado las incidencias y autorizo crear solicitudes reales en Fracttal')
confirmation=st.text_input('Escribe CREAR SOLICITUDES para confirmar',value='')
allowed=confirmed and confirmation.strip()=='CREAR SOLICITUDES'
if st.button('🚀 Crear solicitudes seleccionadas',type='primary',disabled=not allowed):
    results=[]
    try:
        tk=oauth()
        current_refs,_=fetch_all(tk) # vuelve a consultar justo antes de escribir
        bar=st.progress(0)
        for i,(_,row) in enumerate(target.iterrows()):
            ref=str(row['referencia'])
            if ref in current_refs:
                results.append({'referencia':ref,'resultado':'Omitida: ya existe','detalle':''})
            else:
                try:
                    response=request('POST','/work_requests/',tk,payload=body_of(row,user_code.strip(),requested_by.strip(),urgency.startswith('Urgente'),plant_name,asset_code,group,category1,category2))
                    confirmed_remote=bool(isinstance(response,dict) and response.get('success') is True and response.get('data'))
                    if not confirmed_remote:
                        results.append({'referencia':ref,'resultado':'Respuesta sin confirmación','detalle':'Comprobar en Fracttal'})
                        st.error('Respuesta de creación sin confirmación. Verifica Fracttal antes de continuar.');break
                    current_refs.add(ref)
                    photos=photo_map.get(ref,[])
                    if photos:
                        req_id=response_id(response)
                        if req_id is None:
                            results.append({'referencia':ref,'resultado':'Solicitud creada; fotos pendientes','detalle':'La respuesta no incluye id/id_code. Revisar en Fracttal antes de reintentar.'})
                            st.error('Solicitud creada, pero falta identificador para adjuntar fotos. Se detiene el proceso.');break
                        try:
                            n=attach_photos(tk,req_id,photos,images)
                            results.append({'referencia':ref,'resultado':f'Creada con {n} foto(s)','detalle':''})
                        except Exception as attach_error:
                            results.append({'referencia':ref,'resultado':'Solicitud creada; adjuntos pendientes','detalle':str(attach_error)[:180]})
                            st.error('Solicitud creada, pero falló la asociación de fotografías. No vuelvas a crearla: revisa Fracttal y el informe.');break
                    else:
                        results.append({'referencia':ref,'resultado':'Creada sin fotografías','detalle':''})
                except Exception as e:
                    results.append({'referencia':ref,'resultado':'Error / comprobar en Fracttal','detalle':str(e)[:1200]})
                    st.error('Fracttal ha rechazado la petición o no se ha podido confirmar. Lee la columna detalle para conocer la validación y comprueba la solicitud antes de reintentar.');break
            bar.progress((i+1)/len(target))
        if results:
            out=pd.DataFrame(results)
            st.dataframe(out,hide_index=True,use_container_width=True)
            st.download_button('Descargar resultado CSV',data=out.to_csv(index=False).encode('utf-8-sig'),file_name='resultado_importacion_auditorias.csv',mime='text/csv')
            st.session_state.pop('audit_check',None)
    except Exception as e:st.error(str(e))

st.caption('Versión 1.6 · Diagnóstico de errores HTTP: muestra los campos rechazados por Fracttal cuando la API facilita detalles. No muestra contraseñas ni tokens.')
st.caption('Las fotografías solo se transfieren al confirmar la creación. Si falla un adjunto, la solicitud ya creada NO se repite. Fuente: Excel del Departamento de Calidad. API oficial: https://api.fracttal.com/es/reference/crear-una-nueva-solicitud')
