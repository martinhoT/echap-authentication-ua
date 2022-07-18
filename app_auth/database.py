import sqlite3
from hashlib import sha512
from secrets import token_hex
from typing import List

class ProductDatabase:

    def __init__(self, filename='data.db'):
        self._con = sqlite3.connect(filename)
        self._cur = self._con.cursor()

    def user_add(self, username, password, role='regular') -> None:
        salt = self.salt_pass()
        user_add = """
        INSERT INTO user VALUES (?, ?, ?, ?)
        """
        
        self._cur.execute(user_add, (username, self.hash_pass(password, salt), salt, role))
    
    def user_login(self, username, password) -> bool:
        user_search = """
        SELECT * 
        FROM user
        WHERE username = ?
        AND password = ?
        """

        user_salt = """
        SELECT salt
        FROM user
        WHERE username = ?
        """

        self._cur.execute(user_salt, (username,))
        salt_res = self._cur.fetchall()
        if not salt_res:
            return False

        salt = salt_res[0][0]

        self._cur.execute(user_search, (username, self.hash_pass(password, salt)))

        login = self._cur.fetchall()
        return bool(login)
        
    def user_exists(self, username) -> bool:
        user_exists = """
        SELECT *
        FROM user
        WHERE username = ?
        """

        self._cur.execute(user_exists, (username,))
        return bool(self._cur.fetchall())
    
    def user_role(self, username) -> str:
        user_role = """
        SELECT role
        FROM user
        WHERE username = ?
        """

        self._cur.execute(user_role, (username,))
        return self._cur.fetchall()[0][0]

    def user_pass(self, username) -> str:
        user_pass = """
        SELECT password
        FROM user
        WHERE username = ?
        """

        self._cur.execute(user_pass, (username,))
        return self._cur.fetchall()[0][0]

    def user_salt(self, username) -> str:
        user_salt = """
        SELECT salt
        FROM user
        WHERE username = ?
        """

        self._cur.execute(user_salt, (username,))
        return self._cur.fetchall()[0][0]

    def product_add(self, name, price, description, thumbnail):
        product_add = """
        INSERT INTO product VALUES (?, ?, ?, ?)
        """

        self._cur.execute(product_add, (name, price, description, thumbnail))
    
    def product_get_all(self) -> List[list]:
        self._cur.execute('SELECT * FROM product')
        return self._cur.fetchall()
    
    def product_get(self, product_name) -> list:
        product_get = """
        SELECT *
        FROM product
        WHERE name = ?
        """

        self._cur.execute(product_get, (product_name,))
        return self._cur.fetchall()[0]

    def product_search(self, product_name) -> List[list]:
        product_search = """
        SELECT *
        FROM product
        WHERE name LIKE ?
        """

        self._cur.execute(product_search, (product_name,))
        return self._cur.fetchall()

    def sale_get_product(self, user) -> List[list]:
        sale_get_product = """
        SELECT name, price, description, thumbnail, qty
        FROM sale JOIN product ON sale.product=product.name
        WHERE user = ?
        """

        self._cur.execute(sale_get_product, (user,))
        return self._cur.fetchall()

    def sale_add(self, user, product, qty):
        q_qty = """
        SELECT qty
        FROM sale
        WHERE user = ? AND product = ?
        """
        self._cur.execute(q_qty, (user, product))
        qtys = self._cur.fetchall()

        if len(qtys) == 0:
            q_sale_add = """
            INSERT INTO sale (user, product, qty) VALUES (?, ?, ?)
            """
            self._cur.execute(q_sale_add, (user, product, qty))
        
        else:
            q_sale_incr = """
            UPDATE sale
            SET qty = ?
            WHERE user = ? AND product = ?
            """
            self._cur.execute(q_sale_incr, (str(int(qtys[0][0]) + qty), user, product))

    def sale_rem(self, user, product):
        sale_rem = """
        DELETE FROM sale
        WHERE user = ? AND product = ?
        """

        self._cur.execute(sale_rem, (user, product))

    def sale_rem_all(self, user):
        sale_rem_all = """
        DELETE FROM sale WHERE user = ?
        """
        
        self._cur.execute(sale_rem_all, (user,))

    def hash_pass(self, password : str, salt : str) -> str:
        return sha512((password + salt).encode(encoding='utf-8')).hexdigest()
    
    def salt_pass(self) -> str:
        return token_hex(32)

    @property
    def cursor(self):
        return self._cur

    # Allows the usage of the database with the 'with' python clause. Example below
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_value, traceback):
        self._con.commit()
        self._con.close()



# When executed, this script will clean the database in the hardcoded location
# and populate it with data
if __name__=='__main__':

    # Clean database file, in order to start from scratch
    open('data.db', 'w').close()

    with ProductDatabase() as db:

        # Create tables
        db.cursor.execute(
        '''
        CREATE TABLE user(
            username text PRIMARY KEY,
            password text,
            salt text,
            role text)
        '''
        )
        db.cursor.execute(
        '''
        CREATE TABLE product(
            name text PRIMARY KEY,
            price real,
            description text,
            thumbnail text)
        '''
        )
        db.cursor.execute(
        '''
        CREATE TABLE sale(
            sid integer PRIMARY KEY AUTOINCREMENT,
            user text,
            product text,
            qty integer,
            
            FOREIGN KEY(user) REFERENCES user(username),
            FOREIGN KEY(product) REFERENCES product(name))
        '''
        )

        # Populate tables
        db.user_add('john', '1234')
        db.user_add('jolyne', 'secret-pass', 'seller')
        db.user_add('admin', 'admin', 'admin')

        db.product_add('apple', 1.20, 'fruit', '/static/images/apple.png')
        db.product_add('orange', 2.50, 'another fruit', '/static/images/orange.png')
        db.product_add('banana', 0.45, 'yet another fruit', '/static/images/banana.png')
        db.product_add('lima', 0.01, 'last fruit', '/static/images/test.png')

        db.sale_add('john', 'apple', 3)
        db.sale_add('john', 'banana', 2)
