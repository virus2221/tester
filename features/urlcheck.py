
from flask import Blueprint, request, jsonify

urlcheck_bp = Blueprint('urlcheck', __name__)

@urlcheck_bp.route('/urlcheck', methods=['POST'])
def urlcheck_route():
    return jsonify({"message": "This is the /urlcheck endpoint"})
