from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

# Create dummy user
User1 = User(name="Frederick Ankamah", email="frederickankamah988@gmail.com",
             picture='')
session.add(User1)
session.commit()

categories = ['City & Travel', 'Humans', 'Religion', 'Food & Drink', 'Real Estate', 'Education', 'Pet & Vet',
              'Building', 'Hotel', 'Medical', 'Technology', 'Hairdresser']

for category in categories:
    category1 = Category(user_id=1, name=category)
    session.add(category1)
    session.commit()

    for x in xrange(15):
        Item2 = Item(user_id=1, name="item %d" % x, description=" item %d description" %x,
                         price="$0.0", category=category1)
        session.add(Item2)
        session.commit()



