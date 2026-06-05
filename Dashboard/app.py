import dash
from dash import dcc, html, Input, Output
import plotly.express as px
import plotly.graph_objects as go
from data_loader import load_sessions

# Загрузка данных
df, df_sessions, tactic_counts, corr_df, sessions, daily = load_sessions('../Logs/sessions.json')

# Dash приложение
app = dash.Dash(__name__, title='Анализ датасета SSH-сессий')

app.layout = html.Div([
    html.H1('Анализ датасета SSH-сессий', style={'textAlign': 'center'}),

    # Метрики
    html.Div([
        html.Div([
            html.H3(f'{len(df_sessions)}'),
            html.P('Всего сессий')
        ], className='metric-card'),
        html.Div([
            html.H3(f'{len(df_sessions[df_sessions["type"] == "benign"])}'),
            html.P('Benign')
        ], className='metric-card'),
        html.Div([
            html.H3(f'{len(df_sessions[df_sessions["type"] == "malicious"])}'),
            html.P('Malicious')
        ], className='metric-card'),
        html.Div([
            html.H3(f'{len(df_sessions[df_sessions["type"] == "mixed"])}'),
            html.P('Mixed')
        ], className='metric-card'),
    ], style={'display': 'flex', 'justifyContent': 'space-around', 'margin': '20px'}),

    # Графики
    html.Div([
        # Pie chart: типы сессий
        html.Div([
            dcc.Graph(
                figure=px.pie(
                    df_sessions,
                    names='type',
                    title='Распределение типов сессий',
                    color='type',
                    color_discrete_map={'benign': '#2ecc71', 'malicious': '#e74c3c', 'mixed': '#f39c12'}
                )
            )
        ], style={'width': '33%', 'display': 'inline-block'}),

        # Bar chart: тактики
        html.Div([
            dcc.Graph(
                figure=px.bar(
                    tactic_counts,
                    x='Tactic',
                    y='Count',
                    title='Частота тактик MITRE',
                    color='Tactic'
                )
            )
        ], style={'width': '33%', 'display': 'inline-block'}),

        # Histogram: длины сессий
        html.Div([
            dcc.Graph(
                figure=px.histogram(
                    df_sessions,
                    x='num_commands',
                    color='type',
                    title='Распределение длины сессий',
                    nbins=30,
                    color_discrete_map={'benign': '#2ecc71', 'malicious': '#e74c3c', 'mixed': '#f39c12'}
                )
            )
        ], style={'width': '33%', 'display': 'inline-block'}),
    ]),

    # Вторая строка графиков
    html.Div([
        # Top-20 команд
        html.Div([
            dcc.Graph(
                figure=px.bar(
                    df['cmd'].value_counts().head(20).rename_axis('cmd').reset_index(name='count'),
                    x='count',
                    y='cmd',
                    title='Топ-20 команд',
                    orientation='h'
                )
            )
        ], style={'width': '33%', 'display': 'inline-block'}),

        # Heatmap: корреляция тактик
        html.Div([
            dcc.Graph(
                figure=go.Figure(data=go.Heatmap(
                    z=corr_df.values if not corr_df.empty else [[0]],
                    x=corr_df.columns,
                    y=corr_df.columns,
                    colorscale='RdBu',
                    zmin=-1, zmax=1
                )).update_layout(title='Корреляция тактик')
            )
        ], style={'width': '33%', 'display': 'inline-block'}),

        html.Div([
            dcc.Graph(
                figure=px.line(daily, x='date', y='session_id'
                ).update_layout(title='Сессий по дням')
            )


        ], style={'width': '33%', 'display': 'inline-block'})
    ]),

    # Таблица последних сессий
    html.Div([
        html.H3('Последние сессии'),
        dcc.Dropdown(
            id='type-filter',
            options=[
                {'label': 'Все', 'value': 'all'},
                {'label': 'Benign', 'value': 'benign'},
                {'label': 'Malicious', 'value': 'malicious'},
                {'label': 'Mixed', 'value': 'mixed'},
            ],
            value='all'
        ),
        html.Div(id='sessions-table')
    ])
])


@app.callback(
    Output('sessions-table', 'children'),
    Input('type-filter', 'value')
)
def update_table(selected_type):
    if selected_type == 'all':
        filtered = df_sessions
    else:
        filtered = df_sessions[df_sessions['type'] == selected_type]

    return html.Table([
        html.Thead(html.Tr([html.Th(c) for c in ['ID', 'Type', 'IP', 'Username', 'Commands', 'Tactics']])),
        html.Tbody([
            html.Tr([
                html.Td(row['session_id'][:8]),
                html.Td(row['type']),
                html.Td(row['ip']),
                html.Td(row['username']),
                html.Td(row['num_commands']),
                html.Td(row['tactics'][:50] + '...' if len(row['tactics']) > 50 else row['tactics']),
            ]) for _, row in filtered.head(20).iterrows()
        ])
    ])


if __name__ == '__main__':
    app.run(debug=True, port=8050)