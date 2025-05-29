
from flask import Blueprint, request, jsonify

api_bp = Blueprint('api', __name__)

@api_bp.route('/api', methods=['POST'])
def api_route():
    return jsonify({"message": "This is the /api endpoint"})
