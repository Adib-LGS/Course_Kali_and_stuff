from datetime import datetime

tickets = {'opening' : "2004-06-12",
           'closing' : "2024-06-15"}

def resolution_time(opening_date, closing_date):
    opening_date = datetime.strptime(opening_date,'%Y-%m-%d')
    closing_date = datetime.strptime(closing_date,'%Y-%m-%d')
    
    resolution = opening_date - closing_date
    
    return resolution


def add_tickets(tickets, opening_date, closing_date):
    tickets.append({'opening' : opening_date, 'closing' : closing_date})
    
tickets = [
    {'opening': '2024-06-12', 'closing': '2024-06-15'},
    {'opening': '2024-06-10', 'closing': '2024-06-14'},
    {'opening': '2024-06-08', 'closing': '2024-06-13'}
]

for x in tickets:
    opening_date = x['opening']
    closing_date = x['closing']
    resolution = resolution_time(opening_date - closing_date)
    print(f"Ticket opened on {opening_date}, closed on {closing_date}. Resolution time: {resolution}")
    

# Example of dynamically adding a new ticket
add_tickets(tickets, '2024-06-20', '2024-06-25')

# Calculate and print resolution time for the newly added ticket
new_ticket = tickets[-1]
opening_date = new_ticket['opening']
closing_date = new_ticket['closing']
resolution = resolution_time(opening_date, closing_date)
print(f"Newly added ticket - opened on {opening_date}, closed on {closing_date}. Resolution time: {resolution}")