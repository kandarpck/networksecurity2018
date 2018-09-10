import math


# LAB 1
def hello_ta():
    # Your solution here
    print("Hello TA!")
    print("""A second crop of hay lies cut 
and turned. Five gleaming crows
search and peck between the rows.
They make a low, companionable squawk,
and like midwives and undertakers
possess a weird authority.

Crickets leap from the stubble,
parting before me like the Red Sea.
The garden sprawls...""")


hello_ta()


# LAB 2
def pi():
    """
    Computes a rough estimate to the value of pi rounded to 5 decimals.
    Do NOT just return a static value, you must implement the equation
    provided on the wiki. You will not receive credit otherwise.
    >>> pi()
    3.19419
    """
    # Your solution here.
    # pi = 4 * (1 - (1 / 3) + (1 / 5) - (1 / 7) + (1 / 9) - (1 / 11) + (1 / 13) - (1 / 15) + (1 / 17) - (1 / 21) + (
    #         1 / 23) - (1 / 25) + (1 / 27) - (1 / 29) + (1 / 31) - (1 / 33) + (1 / 35) - (1 / 37) + (1 / 39) - (
    #                   1 / 41) + (1 / 43) - (1 / 45) + (1 / 47) - (1 / 49) + (1 / 51) - (1 / 53) + (1 / 55) - (
    #                   1 / 57) + (1 / 59))
    pie = 0
    for x in range(1, 100):
        pie = pie + math.pow(-1.0, x + 1) / (2 * x - 1)
        if abs(3.19419 - (pie * 4)) < 0.001:
            return round(pie * 4, 5)


print(pi())


# LAB 3
def hybrid(car_cost, miles_per_year, cost_of_gas_per_gallon, car_efficiency, car_5_year_resale_value):
    """
    Returns 2 items:
        - the total cost of fuel for 5 years if you bought this car
        - the total cost of owning the car for 5 years (fuel + depreciation in the car's value)

    Parameters:
        car_cost: the amount the car costs upon initial purchase
        miles_per_year: the amount of miles you expect to drive per year
        cost_of_gas_per_gallon: the cost of a gallon of gas
        car_efficiency: expected miles per gallon of the car
        car_5_year_resale_value: the expected value of the car after 5 years

    >>> hybrid(10000, 2000, 2.50, 40, 7500)
    (625.0, 3125.0)
    """
    # Your solution here.
    fuel_cost = miles_per_year * cost_of_gas_per_gallon / car_efficiency * 5
    total_cost = fuel_cost + (car_cost - car_5_year_resale_value)
    return fuel_cost, total_cost


print(hybrid(10000, 2000, 2.50, 40, 7500))

import random


# LAB 4
def montehall(num_iterations=1000):
    """
    Runs the Monty Hall simulation num_iterations times.

    Returns 2 values:
        - a counter which keeps track of if you do switch doors and win.
        - a counter which keeps track of if you don't switch doors and win.

    >>> switch, no_switch = montehall()
    >>> switch + no_switch
    1000
    >>> switch > no_switch
    True
    >>> switch, no_switch = montehall(200)
    >>> switch + no_switch
    200
    >>> switch > no_switch
    True
    """
    # Your solution here.
    no_switch_win = 0
    for iterations in range(num_iterations):
        car_door = random.randint(1, 3)
        contestant_door = random.randint(1, 3)
        removed_door = None
        while not removed_door:
            remove_pick = random.randint(1, 3)
            if not (remove_pick == car_door or remove_pick == contestant_door):
                removed_door = remove_pick
        if car_door == contestant_door:
            no_switch_win += 1

    return num_iterations - no_switch_win, no_switch_win


print(montehall(100))


# LAB 5
def hotplate(matrix):
    """
    Returns a 2D matrix in which the heat distribution has stabilized.
    We define stabilization as if no values in the matrix change by
    no more than 0.1.

    >>> matrix = [ [0.0, 100.0, 30.7],\
                   [10.5, 45.0, 50.3],\
                   [11.1, 33.5, 48.2]]
    >>> hotplate(matrix)
    [[0.04744, 0.04395, 0.04744], [0.04395, 0.09487, 0.04395], [0.04744, 0.04395, 0.04744]]
    """
    # Your solution here.
    pass


# LAB 6
def pig_latin(input):
    """
    Returns the input translated into pig latin.

    >>> pig_latin("i wrote this program because i can not speak pig latin")
    "iay otewray isthay ogrampray ecuasebay iay ancay otnay eakspay igpay atinlay"
    """
    # Your solution here
    vowles = ['a', 'e', 'i', 'o', 'u']
    input_array = input.split(" ")
    for idx, item in enumerate(input_array):
        if item[0] not in vowles:
            if item[1] not in vowles:
                input_array[idx] = item[2:] + item[:2] + "ay"
            else:
                input_array[idx] = item[1:] + item[:1] + "ay"
        else:
            input_array[idx] = item + "ay"
    return " ".join(input_array)


print(pig_latin("i wrote this program because i can not speak pig latin"))

from collections import Counter
import string


# LAB 7
def unique_words(input):
    """
    Returns a mapping of unique words and the count
    of how often they appear in the input text.

    >>> input_text = "This is a sentence with some repeated words and some non-repeated words."
    >>> mapping = unique_words(input_text)
    >>> mapping['this']
    1
    >>> mapping['is']
    1
    >>> mapping['a']
    1
    >>> mapping['repeated']
    1
    >>> mapping['some']
    2
    >>> mapping['words']
    2
    """
    # Your solution here.

    return Counter(input.lower().translate(str.maketrans({key: None for key in string.punctuation})).split(" "))


input_text = "This is a sentence with some repeated words and some non-repeated words."
mapping = unique_words(input_text)
print(mapping['this'])
print(mapping['words'])


# LAB 8
class Team:

    def __init__(self, name):
        self.name = name
        self.wins = 0
        self.loses = 0
        self.total_points_scored = 0
        self.highest_points = 0


def parse_through_game_records(list_of_games):
    """
    Goes through the each game and updates the records
    of each team seen. Each game will have a winner and a loser.
    The wining team will update the number of wins it has, the number
    of total points scored, and the highest points scored in a game.

    This should return a mapping between team names and Team objects.
    See example test case below.

    >>> all_teams = parse_through_game_records(["BYU 14 Hopkins 17", "Hopkins 21 Yale 10"])
    >>> all_teams["BYU"].name
    'BYU'
    >>> all_teams["Hopkins"].name
    'Hopkins'
    >>> all_teams["Hopkins"].wins
    0
    >>> all_teams["BYU"].wins
    1
    >>> all_teams["OldMiss"].loses
    0
    """
    # Your solution here
    all_teams = dict()
    for game in list_of_games:
        game_items = game.split(" ")
        if all_teams.get(game_items[0]):
            team1 = all_teams[game_items[0]]
        else:
            team1 = Team(name=game_items[0])
            all_teams[game_items[0]] = team1
        if all_teams.get(game_items[2]):
            team2 = all_teams[game_items[2]]
        else:
            team2 = Team(name=game_items[2])
            all_teams[game_items[2]] = team2
        team1.name = game_items[0]
        team2.name = game_items[2]
        team1_score = int(game_items[1])
        team2_score = int(game_items[3])
        if team1_score > team2_score:
            team1.wins += 1
            team2.loses += 1
        else:
            team2.wins += 1
            team1.loses += 1
        team1.total_points_scored += team1_score
        team2.total_points_scored += team2_score
    return all_teams


all_teams = parse_through_game_records(["BYU 14 Hopkins 17", "Hopkins 21 Yale 10"])
print(all_teams['Hopkins'].name)
print(all_teams['Hopkins'].wins)
print(all_teams['BYU'].wins)


def get_statistics(list_of_games):
    """
    Given that you have implemented the above function,
    return the following statistics:
        - which team won the most games during the season?
        - which team scored the most points in a single game?
        - which team scored the most points during the whole season?

    >>> most_wins, most_single_points, most_total_points = get_statistics(["BYU 14 Hopkins 17", "Hopkins 21 Yale 10"])
    >>> most_wins.name
    'Hopkins'
    >>> most_single_points.name
    'Hopkins'
    >>> most_total_points.name
    'Hopkins'
    """
    # Your solution here
    pass


# LAB 9
class Customer:

    def __init__(self, name):
        self.name = name
        self.value = None
        self.bonds = None
        self.checking_accounts = None


class Bond:

    def __init__(self, name, issue_year, init_value, return_rate):
        self.name = name
        self.issue_year = issue_year
        self.init_value = init_value
        self.return_rate = return_rate


class CheckingAccount:

    def __init__(self, name, value):
        self.name = name
        self.value = value


def parse_through_bank_records(list_of_bank_records):
    """
    Given a list of bank records in this format:

    'customer Mark
    checking myaccount 100.00
    bond mybond1 1997 100 0.07
    bond mybond2 2010 200 0.01'

    parse through each record and update each customer's portfolio,
    namely the bonds that belong to them, the various checking
    accounts that they own, and the total value of all their assets to this date.
    You may import any libraries you may need.

    * Calculate interest rates on a whole year scale, i.e. if you have a 7% interest rate on
    a $100, you receive your $7 at the start of the next year. Assume bonds were received at
    the start of the year i.e. January 1st.

    >>> list_of_bank_records = ['customer Mark checking myaccount 100.00 bond mybond1 1997 100 0.07 bond mybond2 2010 200 0.01']
    >>> customers = parse_through_bank_records(list_of_bank_records)
    >>> customers['Mark'].value
    527.06
    >>> len(customers['Mark'].bonds)
    2
    """
    # Your solution here.
    pass


# LAB 10
def text_like_file(input):
    """
    Given an input string, that will represent a document filled with sentences,
    generate some text according to the wiki page.
    """
    # Your solution here.
    pass


# LAB 11

class Person:
    # Your solution here.
    pass


def family_history(list_of_inputs):
    """
    Given a list of people records in this format:
        FirstName LastName Identifier FatherIdentifier MotherIdentifier BirthYear BirthCity, BirthState, BirthCountry

    parse through them and create a Person object. Then create a mapping between an ID and the person object.
    Return that mapping.

    >>> family_history_input = [
    "George Bush 016873 001244 001243 1946 New Haven, Connecticut, USA",
    "George Bush 001244 000364 000367 1924 Milton, Massachusetts, USA",
    "Barbara Pierce 001243 000372 000298 1925 New York City, New York, USA",
    "Jed Bush 07465 001244 001243 1947 Miami, Florida, USA",
    "Mary Bush 17309 001244 001243 1948 Provo, Utah, USA",
    "Martin Frank 99934 88845 17309 1968 Kanab, Utah, USA",
    "Gary Haws 77745 99934 66623 1988 Nephi, Utah, USA",
    "Margie Smith 000367 111023 111024 1926 Orem, Utah, USA",
    "John Bush 000364 211023 211024 1927 Eugene, Oregon, USA",
    "Wilma Flinstone 211024 311023 311876 1907 Sacramento, California, USA",
    ]
    >>> family_history_mapping = family_history(family_history_input)
    >>> isinstance(family_history_mapping["016873"], Person)
    True
    >>> family_history_mapping["016873"].name
    'George Bush'
    """
    # Your solution here.
    pass


def get_ancestry_line(family_history_mapping, identifier):
    """
    Returns a list of names that were ancestors to the input identifier, that we have a record of.
    The list of names should include both father and mother, in that order, and in order of generation.
    Concretely, the ordering should be the person being searched, their father, their mother,
    their father's father, their father's mother, their mother's father, their mother's mother, etc.

    >>> family_history_input = [
    "George Bush 016873 001244 001243 1946 New Haven, Connecticut, USA",
    "George Bush 001244 000364 000367 1924 Milton, Massachusetts, USA",
    "Barbara Pierce 001243 000372 000298 1925 New York City, New York, USA",
    "Jed Bush 07465 001244 001243 1947 Miami, Florida, USA",
    "Mary Bush 17309 001244 001243 1948 Provo, Utah, USA",
    "Martin Frank 99934 88845 17309 1968 Kanab, Utah, USA",
    "Gary Haws 77745 99934 66623 1988 Nephi, Utah, USA",
    "Margie Smith 000367 111023 111024 1926 Orem, Utah, USA",
    "John Bush 000364 211023 211024 1927 Eugene, Oregon, USA",
    "Wilma Flinstone 211024 311023 311876 1907 Sacramento, California, USA",
    ]
    >>> family_history_mapping = family_history(family_history_input)
    >>> get_ancestry_line(family_history_mapping, '016873')
    # self,    f(ather), m(other), ff,       fm,        mf,      mm,        fff,     ffm,      fmf,      fmm,      ffmf,     ffmm
    ['016873', '001244', '001243', '000364', '000367', '000372', '000298', '211023', '211024', '111023', '111024', '311023', '311876']
    """
    # Your solution here.
    pass
