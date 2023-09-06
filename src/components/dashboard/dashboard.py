from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, DateField, validators, SelectField
from wtforms.validators import DataRequired, Email, EqualTo


def build_pie_chart_data(stock_json):
    sector_data = {}

    for stock in stock_json['stocks']:
        sector = stock['sector']
        total_invested = stock['totalInvested']

        if sector in sector_data:
            sector_data[sector] += total_invested
        else:
            sector_data[sector] = total_invested

    pie_chart_data = {
        "pieChartData": [{"sector": key, "value": value} for key, value in sector_data.items()]
    }
    
    return pie_chart_data

def build_market_cap_chart_data(stock_json):
    market_cap_count = {}

    # Count occurrences of each market cap
    for stock in stock_json['stocks']:
        marketCap = stock['marketCap']['name']
        market_cap_count[marketCap] = market_cap_count.get(marketCap, 0) + 1

    pie_chart_data = {
        "pieChartData": [{"stockName": key, "value": value} for key, value in market_cap_count.items()]
    }
    
    return pie_chart_data


def build_stock_allocation_percentage_data(stock_json):
    stocks = stock_json['stocks']
    total_market_cap = sum([stock['marketCap']['value'] for stock in stocks])
    allocations = [(stock['symbol'], (stock['marketCap']['value'] / total_market_cap) * 100) for stock in stocks]
    
    return allocations


class StockForm(FlaskForm):
    stock_symbol = StringField('Stock Symbol', validators=[DataRequired()])
    entry_price = FloatField('Entry Price', validators=[DataRequired()])
    stock_quantity = FloatField('Quantity', validators=[DataRequired()])
    entry_date = DateField('Entry Date', validators=[DataRequired()])
    submit = SubmitField('Add Stock Entry')