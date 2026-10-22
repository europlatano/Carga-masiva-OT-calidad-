"""Europlátano: importador controlado de hallazgos de auditoría a solicitudes Fracttal.
Sin borrados, sin crear órdenes de trabajo. No conserva ficheros entre sesiones.
"""
from __future__ import annotations
import hashlib, hmac, io, re, unicodedata
from collections import Counter
from datetime import datetime, date, timezone
from zoneinfo import ZoneInfo
import requests
import pandas as pd
import streamlit as st

API = 'https://app.fracttal.com/api'
TOKEN_URL = 'https://one.fracttal.com/oauth/token'
APP_VER = '1.0'
st.set_page_config(page_title='Calidad → Fracttal | Europlátano', page_icon='📋', layout='wide')
st.title('📋 Auditorías de Calidad → Solicitudes Fracttal')
st.caption('Europlátano · V1 · IFS / GLOBALG.A.P. · No crea órdenes de trabajo')

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

def ident(date_val, area, incidence, occurrence):
    # Referencia estable entre exportaciones aun si cambian el orden de filas.
    seed='|'.join((dtstr(date_val),norm(area),norm(incidence),str(occurrence)))
    return 'CAL-IFS-PAL-'+hashlib.sha256(seed.encode('utf-8')).hexdigest()[:16].upper()

def extract(blob):
    frame=pd.read_excel(io.BytesIO(blob),sheet_name=0,header=1,engine='openpyxl',dtype=object)
    if frame.shape[1]<10: raise ValueError('El Excel no contiene las diez columnas esperadas de Calidad.')
    result=[]; occurred=Counter()
    for ix,raw in frame.iterrows():
        row=list(raw.values)
        incident=clean(row[3]); area=clean(row[2]); status=clean(row[9]); dept=clean(row[6]); day=dtstr(row[1])
        if not incident or not day: continue
        signature=(day,norm(area),norm(incident));occurred[signature]+=1
        ref=ident(row[1],area,incident,occurred[signature])
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

def request(method,endpoint,token,*,payload=None,params=None):
    headers={'Authorization':'Bearer '+token,'Accept':'application/json'}
    if payload is not None: headers['Content-Type']='application/json'
    res=requests.request(method,API+endpoint,headers=headers,json=payload,params=params,timeout=40)
    try: body=res.json()
    except ValueError: body={}
    if res.status_code>=400 or (isinstance(body,dict) and body.get('success') is False):
        msg=body.get('message') if isinstance(body,dict) else None
        # No mostramos cuerpo crudo (potencialmente datos sensibles).
        msg=str(msg)[:160] if isinstance(msg,str) and not any(x in msg.lower() for x in ('token','secret','password')) else 'Revisar permisos o datos obligatorios.'
        raise RuntimeError(f'{method} {endpoint}: HTTP {res.status_code}. {msg}')
    return body

def fetch_all(token):
    # La documentación no garantiza una semántica de paginación idéntica en todas las cuentas.
    # Si no es verificable, impedimos importar para evitar duplicados.
    data=request('GET','/work_requests/',token,params={'since':'2023-01-01T00:00:00-00','until':datetime.now(timezone.utc).strftime('%Y-%m-%dT23:59:59-00')})
    if not isinstance(data,dict) or not isinstance(data.get('data'),list):
        raise RuntimeError('Fracttal no devolvió una lista verificable de solicitudes.')
    found=data['data']; total=data.get('total')
    if total not in (None,''):
        try:
            if int(total)>len(found):
                raise RuntimeError('Fracttal devolvió una consulta parcial (%s de %s). No se permite importar hasta configurar paginación segura.'%(len(found),total))
        except ValueError: pass
    # Una cuenta puede tener más solicitudes antiguas fuera del intervalo; cada identificador de auditoría empieza con prefijo y se busca además por referencia.
    refs={str(x.get('identifier') or '').strip() for x in found if isinstance(x,dict)}
    return refs,len(found)

def title(row):
    text=re.sub(r'\s+',' ',str(row['incidencia'])).strip()
    return ('AUDITORÍA IFS · '+text)[:200]

def body_of(row,user_code,requested_by,urgent):
    parts=[f"Origen: inspección interna IFS · Palomares",f"Referencia: {row['referencia']}",f"Fecha de detección: {row['fecha']}",f"Zona/área: {row['zona']}",f"Hallazgo de Calidad: {row['incidencia']}"]
    for label,col in [('Acción correctiva indicada por Calidad','accion_calidad'),('Evidencia','evidencia'),('Responsable en Excel','responsable'),('Fecha objetivo de cierre','fecha_prevista'),('Observaciones','observaciones')]:
        val=str(row.get(col,'')).strip()
        if val: parts.append(f'{label}: {val}')
    return {'user_code':user_code,'user_type':'HUMAN_RESOURCES','description':title(row),
      'observation':'\n'.join(parts),'date_incident':row['fecha']+'T12:00:00-00',
      'requested_by':requested_by[:200], 'identifier':row['referencia'],'is_urgent':bool(urgent)}

upload=st.file_uploader('1 · Selecciona el Excel original del Departamento de Calidad',type=['xlsx'])
if upload is None:
    st.info('Sube el Excel de Inspecciones internas IFS de Palomares. Por defecto se seleccionarán únicamente las incidencias ABIERTAS asignadas a Mantenimiento, incluidas las compartidas.');st.stop()
blob=upload.getvalue()
try: df=extract(blob)
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
# Se puede desmarcar individualmente. Las filas no seleccionadas por defecto se muestran desmarcadas.
cols=['seleccion','fila_excel','fecha','zona','incidencia','responsable','estado','referencia']
edited=st.data_editor(view[cols],hide_index=True,use_container_width=True,num_rows='fixed',key='quality_editor_'+str(choices.index(mode)),disabled=[c for c in cols if c!='seleccion'],column_config={'seleccion':st.column_config.CheckboxColumn('Importar'), 'incidencia':st.column_config.TextColumn('Hallazgo',width='large'),'zona':st.column_config.TextColumn('Zona',width='medium')})
selected_refs=set(edited.loc[edited['seleccion']==True,'referencia'].tolist())
selected=df[df.referencia.isin(selected_refs)].copy()
st.caption(f'Seleccionadas para revisión: {len(selected)}. Cada hallazgo conservará una referencia estable para evitar duplicados.')
if selected.empty:st.stop()

st.subheader('4 · Configuración de Fracttal')
def_user=sec('FRACTTAL_REQUEST_USER_CODE')
user_code=st.text_input('Código del usuario/recurso humano que registrará la solicitud (obligatorio)',value=def_user,help='Es user_code, NO el nombre ni el email. Lo puedes guardar en Secrets como FRACTTAL_REQUEST_USER_CODE.')
requested_by=st.text_input('Solicitante (obligatorio)',value='Departamento de Calidad – Europlátano')
urgency=st.selectbox('Urgencia por defecto', ['No urgente (recomendado)','Urgente (solo si procede)'])
st.caption('La zona y la referencia del hallazgo se incluyen en la descripción. No se asocia un activo si no se conoce su código exacto. La prioridad de Fracttal se gestiona mediante is_urgent.')
if not user_code.strip() or not requested_by.strip(): st.warning('Completa el código de usuario y el solicitante para continuar.');st.stop()

st.subheader('5 · Comprobar duplicados (solo lectura)')
filetag=hashlib.sha256(blob).hexdigest()[:12]
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
                    response=request('POST','/work_requests/',tk,payload=body_of(row,user_code.strip(),requested_by.strip(),urgency.startswith('Urgente')))
                    confirmed_remote=bool(isinstance(response,dict) and response.get('success') is True and response.get('data'))
                    results.append({'referencia':ref,'resultado':'Creada' if confirmed_remote else 'Respuesta sin confirmación','detalle':''})
                    if confirmed_remote:current_refs.add(ref)
                    else:
                        # Si la respuesta no confirma, no continuamos para evitar duplicados.
                        st.error('Respuesta de creación sin confirmación suficiente. Verifica Fracttal antes de continuar.');break
                except Exception as e:
                    results.append({'referencia':ref,'resultado':'Error / comprobar en Fracttal','detalle':str(e)[:180]})
                    st.error('Se ha detenido la importación para evitar duplicados. Comprueba la solicitud antes de reintentar.');break
            bar.progress((i+1)/len(target))
        if results:
            out=pd.DataFrame(results)
            st.dataframe(out,hide_index=True,use_container_width=True)
            st.download_button('Descargar resultado CSV',data=out.to_csv(index=False).encode('utf-8-sig'),file_name='resultado_importacion_auditorias.csv',mime='text/csv')
            st.session_state.pop('audit_check',None)
    except Exception as e:st.error(str(e))

st.caption('Fuente: Excel del Departamento de Calidad. API oficial: https://api.fracttal.com/es/reference/crear-una-nueva-solicitud')
