import requests
import pandas as pd
from flask import Flask, request, jsonify, render_template, flash, redirect, url_for
from recommend import MovieManager
import json
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_login import login_required
import warnings
warnings.filterwarnings("ignore")

movieManager = MovieManager()
app = Flask(__name__)
app.config.update(
    TESTING=True,
    SECRET_KEY="password"
)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


movie_links = pd.read_csv(
    "D:\\final\Movie recommendations system\ml-latest-small\movie_links.csv")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('home'))
    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)



def get_tmdbId(movieId):
    """
    Given a movieId and a DataFrame with columns 'movieId', 'title', and 'tmdbId',
    returns the tmdbId for that movie.
    """
    movie_row = movie_links[movie_links['movieId'] == movieId]
    if len(movie_row) == 0:
        raise ValueError(f"No movie found with movieId {movieId}")
    return movie_row.iloc[0]['tmdbId']


api_key = "5bda0a39e6f7abce03804df5779fc584"


def get_movie_detials(tmdbId):
    """
    Given a TMDb movie ID and an API key, retrieves the details of the movies.
    """
    # Build the API URL
    url = f"https://api.themoviedb.org/3/movie/{tmdbId}?api_key={api_key}&language=en-US"

    # Send a GET request to the API and parse the JSON response
    response = requests.get(url)
    response_json = json.loads(response.text)

    # Extract the details of the movie from the response JSON
    movie_details = {
        "title": response_json["original_title"],
        "overview": response_json["overview"],
        "poster_url": f"https://image.tmdb.org/t/p/w500{response_json['poster_path']}",
        "genres": [genre["name"] for genre in response_json["genres"]],
        "release_date": response_json["release_date"],
        "tmdb_url": f"https://www.themoviedb.org/movie/{tmdbId}",
        "vote_average": response_json["vote_average"],
        "vote_count": response_json["vote_count"]
    }

    return movie_details


@app.route('/', methods=["POST", "GET"])
@app.route("/home", methods=["POST", "GET"])
@login_required
def home():
    error = False
    error_message = ""
    movie_list = movieManager.get_movie_list()

    try:
        if request.method == "POST":
            movie_form_input = request.form["movie_input"]
            try:
                rating_form_input = int(request.form["rating_input"])
            except Exception as e:
                print("EXCEPTION: at rating_form_input")

            if movie_form_input and rating_form_input:
                movieManager.add_movie([movie_form_input, rating_form_input])
                flash(f"Successfully added [{movie_form_input}]", "info")
            else:
                error = True
                error_message = "Movie Input box Empty"
                print("No movie Added , Detected Empty form")

            print(f"{movie_form_input} added")
    except Exception as e:
        print(f"EXCEPTION AT HOME: {e}")
        print("MOVIE NOT IN DB")

    return render_template("home.html", error=error, error_msg=error_message, movie_list=json.dumps(movie_list))


@app.route("/get_recommend", methods=["POST"])
@login_required
def get_recommendation():
    recommend_movies = movieManager.getRecommendations(
        movieManager.get_watched_movie())
    movieManager.clear_movie_index()
    movieManager.get_all_movies_index(recommend_movies)

    reco_movies_index_list = movieManager.recommended_movies_index
    reco_movies_tmdbId = [get_tmdbId(movie_id)
                          for movie_id in reco_movies_index_list]
    reco_movies_details = [get_movie_detials(
        tmdb_id) for tmdb_id in reco_movies_tmdbId]
    print(type(reco_movies_details))
    reco_movies_dict = list(
        zip(recommend_movies, reco_movies_index_list, reco_movies_details))

    return jsonify('', render_template('recommend.html', MOVIE_DATA=reco_movies_dict))


@app.route("/display_recommendation")
def display_recommendation():
    '''
        when get_recommendation is clicked
            display all recommended movies
    '''
    pass


@app.route("/clear_movies", methods=["POST", "GET"])
def clear_existing_movies():
    movieManager.clear_movie()
    log_message = "Movies Cleared"
    print("Movies Cleared")

    return jsonify('', render_template('recommend.html', LOG=log_message))


if __name__ == '__main__':
    app.run(debug=True)
