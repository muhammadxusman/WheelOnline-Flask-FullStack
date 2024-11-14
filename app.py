from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, get_jwt, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
from datetime import timedelta
pymysql.install_as_MySQLdb()
from sqlalchemy.dialects.postgresql import JSON
import os
from werkzeug.utils import secure_filename
app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:usman0336@localhost:3306/wheelsonline"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = "supersecretkey"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)


db = SQLAlchemy(app)
jwt = JWTManager(app)

# Define where to save uploaded images
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'Images')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/')
def home():
    return render_template("home.html")

@app.route('/dashboard')
def dashboard():
    return render_template("UserDashboard.html")

@app.route('/dashboard/upload')
def UploadSection():
    return render_template("UploadSection.html")


@app.route('/used-car')
def Used_car():
    return render_template("UsedCar.html")

@app.route('/super-admin-dashboard/upload')
def sa_upload():
    return render_template("SaUploadCar.html")


@app.route('/super-admin-dashboard')
def SuperAdmindashboard():
    return render_template("SaDashboard.html")

@app.route('/super-admin-dashboard/update-ads')
def Sa_update_ads():
    return render_template("Saupdate.html")




# Role Model
class Role(db.Model):
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(100), nullable=False)

    @staticmethod
    def insert_roles():
        # First insert 'super_admin' role if it doesn't exist
        super_admin_role = Role.query.filter_by(name="super_admin").first()
        if not super_admin_role:
            super_admin_role = Role(name="super_admin", description="Super Administrator with full access")
            db.session.add(super_admin_role)

        # Insert 'user' role if it doesn't exist
        user_role = Role.query.filter_by(name="user").first()
        if not user_role:
            user_role = Role(name="user", description="Regular user with limited access")
            db.session.add(user_role)

        # Commit to save the changes in the database
        db.session.commit()

        # Ensure there is at least one super admin user
        super_admin_email = "superadmin@gmail.com"  # You can change this email
        super_admin_user = User.query.filter_by(email=super_admin_email).first()

        if not super_admin_user:
            # Create super admin user if it doesn't exist
            hashed_password = generate_password_hash("admin123")  # Default super admin password
            super_admin_user = User(
                email=super_admin_email,
                name=super_admin_role.name,
                password=hashed_password,
                roleId=super_admin_role.id
            )
            db.session.add(super_admin_user)
            db.session.commit()

# User Model
class User(db.Model):
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    roleId = db.Column(db.Integer, db.ForeignKey('role.id'))  # Foreign key linking to Role table
    email = db.Column(db.String(40), nullable=False, unique=True)
    name = db.Column(db.String(40), nullable=False)
    password = db.Column(db.String(1000), nullable=False)

    # Relationship with Role model
    role = db.relationship('Role', backref='users', lazy=True)

@app.route('/register', methods=["GET", "POST"])
def sign_up():
    if request.method == "POST":
        data = request.form
        email = data.get('email')
        name = data.get('name')
        password = data.get('password')
        role_name = data.get('role', 'user')  # Default role is 'user'

        if not email or not name or not password:
            return jsonify({"error": "The fields are empty"})

        if User.query.filter_by(email=email).first():
            return jsonify({"Error": "Email already exists...!"})

        # Get role ID based on role_name
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            return jsonify({"Error": "Invalid role specified"}), 400

        hashed_password = generate_password_hash(password)
        newUser = User(email=email, name=name, password=hashed_password, roleId=role.id)

        db.session.add(newUser)
        db.session.commit()

        return jsonify({"Success": "User registered successfully"})
    return render_template("signup.html")




@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.get_json()  # Receive JSON data instead of form data
        email = data.get("email")
        password = data.get("password")
        userId = data.get("user")

        if not email or not password:
            return jsonify({"error": "Fields are missing"})

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            # Fetch user's role name
            role_name = user.role.name

            # Create an access token with additional claims for name and role
            access_token = create_access_token(
                identity=email,
                additional_claims={
                    "userId": user.id,
                    "name": user.name,
                    "role": role_name
                }
            )
            return jsonify({"access_token": access_token}), 200

        return jsonify({"error": "Invalid username or password"}), 401
    return render_template("login.html")





# New endpoint to list all users (Only accessible by super_admin)
@app.route('/list_users', methods=["GET"])
@jwt_required()
def list_users():
    # Get the current logged in user's email from JWT
    current_user_email = get_jwt_identity()

    # Find the current user
    current_user = User.query.filter_by(email=current_user_email).first()

    if not current_user or current_user.role.name != "super_admin":
        return jsonify({"error": "You do not have permission to view this resource."}), 403

    # Fetch all users
    users = User.query.all()
    users_list = [{"id": user.id, "name": user.name, "email": user.email} for user in users]
    
    return jsonify({"users": users_list}), 200






class Cars(db.Model):
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    userId = db.Column(db.Integer, db.ForeignKey('user.id'))  
    carTitle = db.Column(db.String(40), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    model = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(500), nullable=False)
    images = db.Column(JSON, nullable=False)  # Store images as a JSON list of paths
    NewCar = db.Column(db.String(50), nullable=False)
    status = db.Column(db.Integer, nullable=False, default=0)
    role = db.relationship('User', backref='users', lazy=True)
 


@app.route('/submit-data', methods=['POST'])
@jwt_required()
def submitData():
    print("Request form data:", request.form)
    print("Request files data:", request.files)

    # Retrieve the current user ID from JWT claims
    claims = get_jwt()
    current_userId = claims.get("userId")
    car_title = request.form.get("carTitle")
    price = request.form.get("price")
    model = request.form.get("model")
    description = request.form.get("description")
    new_car = request.form.get("newCar") 


    # Validate that required fields are present
    if not all([car_title, price, model, description, new_car]):
        print("Error: Missing fields")
        return jsonify({"error": "Some fields are missing"}), 400

    # Handle multiple image files
    images = request.files.getlist("images")
    image_paths = []

    for image in images:
        if image:
            # Secure the filename and save the image
            filename = secure_filename(image.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            print(f"Saving image to {filepath}")
            image.save(filepath)
            image_paths.append(filepath)  # Append the file path to the list

    # Create new car data entry
    new_car_data = Cars(
        userId=current_userId,
        carTitle=car_title,
        price=price,
        model=model,
        description=description,
        images=image_paths,  # Store the list of file paths
        NewCar=new_car
    )

    db.session.add(new_car_data)
    db.session.commit()

    print("Car data submitted successfully")
    return jsonify({"success": "Car data submitted successfully"}), 201




@app.route('/submit-data-sa', methods=['POST'])
@jwt_required()
def submitData_():
    print("Request form data:", request.form)
    print("Request files data:", request.files)

    # Retrieve the current user ID from JWT claims
    claims = get_jwt()
    current_userId = claims.get("userId")
    car_title = request.form.get("carTitle")
    price = request.form.get("price")
    model = request.form.get("model")
    description = request.form.get("description")
    new_car = request.form.get("newCar") 


    # Validate that required fields are present
    if not all([car_title, price, model, description, new_car]):
        print("Error: Missing fields")
        return jsonify({"error": "Some fields are missing"}), 400

    # Handle multiple image files
    images = request.files.getlist("images")
    image_paths = []

    for image in images:
        if image:
            # Secure the filename and save the image
            filename = secure_filename(image.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            print(f"Saving image to {filepath}")
            image.save(filepath)
            image_paths.append(filepath)  # Append the file path to the list

    # Create new car data entry
    new_car_data = Cars(
        userId=current_userId,
        carTitle=car_title,
        price=price,
        model=model,
        description=description,
        images=image_paths,  # Store the list of file paths
        NewCar=new_car,
        status= 1
    )

    db.session.add(new_car_data)
    db.session.commit()

    print("Car data submitted successfully")
    return jsonify({"success": "Car data submitted successfully"}), 201




@app.route('/show-car', methods=["GET"])
def show_car():
    # showAllCar = Cars.query.filter_by(Cars.status == 1)
    showAllCar = Cars.query.all()
    if showAllCar:
        AvlCars = []
        for car in showAllCar:
            allAvlCars = {
                "car_Id": car.id,
                "car_title": car.carTitle,
                "price": car.price,
                "model": car.model,
                "description": car.description,
                "images": car.images,
                "new_car": car.NewCar,
                "status":car.status
            }
            AvlCars.append(allAvlCars)  
        return jsonify(AvlCars), 200  
    return jsonify({"error": "no car found"}), 400

@app.route('/update-status', methods=["PUT"])
@jwt_required()
def update_status():
    current_user_email = get_jwt_identity()
    if current_user_email != "superadmin@gmail.com":
        return jsonify({"error": "Only the super admin can update car status"}), 403

    data = request.get_json()  # Use request.get_json() to retrieve the JSON body
    print("Data received in update-status:", data)  # Debugging line
    
    car_id = data.get("car_id")
    new_status = data.get("status")

    if car_id is None or new_status is None:
        return jsonify({"error": "car_id and status are required"}), 400

    car = Cars.query.get(car_id)
    if not car:
        return jsonify({"error": "Car not found"}), 404

    car.status = new_status
    db.session.commit()
    return jsonify({"success": f"Car status updated to {new_status} for car ID {car_id}"}), 200


@app.route('/user-ads', methods=["GET"])
@jwt_required()
def user_ads():
    claims = get_jwt()
    current_userId = claims.get("userId")

    data = Cars.query.filter_by(userId=current_userId).all()
    if data:
        allData = []
        for vehical in data:
            # Assuming the full path includes '/Users/usmanali/Desktop/Fl/Images/', so we need to remove it
            image_urls = [f"/static/images/{img.split('/')[-1]}" for img in vehical.images]
            
            fetch = {
                "VehicalTitle": vehical.carTitle,
                "Price": vehical.price,
                "Model": vehical.model,
                "Description": vehical.description,
                "Images": image_urls,
            }
            allData.append(fetch)
        return jsonify(allData), 200
    return jsonify({"error": "No data found"}), 400


@app.route('/show-all-user')
@jwt_required()
def show_all_user():
    # Get the current user based on the token
    current_user_email = get_jwt_identity()
    current_user = User.query.filter_by(email=current_user_email).first()

    # Check if the user has super_admin role
    if current_user and current_user.role.name == "super_admin":
        
        # Retrieve all users
        # all_users = User.query.filter_by( User.role.name == "user")
        all_users = User.query.join(Role).filter(Role.name == "user").all()
        # Prepare user data
        if all_users:
            userfetched = []
            for user in all_users:
                user_data = {
                    "email": user.email,
                    "name": user.name,
                    "role_name": user.role.name
                }
                userfetched.append(user_data)
            
            return jsonify(userfetched), 200
        else:
            return jsonify({"error": "No User Found"}), 404
    # If the current user is not authorized (not super_admin)
    return jsonify({"error": "Unauthorized access"}), 403
   


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create tables
        Role.insert_roles()  # Ensure roles are inserted first
    app.run(debug=True)
    app.run()