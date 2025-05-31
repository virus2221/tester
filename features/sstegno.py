from flask import Blueprint, request, jsonify
import cv2
import numpy as np
from scipy.stats import chisquare
import scipy.fftpack as fftpack
from skimage.measure import shannon_entropy
import os
import uuid
from flask_cors import CORS
import base64
from werkzeug.utils import secure_filename

sstegno_bp = Blueprint('sstegno', __name__)
CORS(sstegno_bp)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_extension(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def analyze_video(video_path):
    cap = cv2.VideoCapture(video_path)
    frame_count = 0
    results = {
        'suspicious_frames': [],
        'dct_anomalies': [],
        'entropy_anomalies': [],
        'lsb_distribution': [],
        'frame_count': 0,
        'chi_square': {'statistic': None, 'p_value': None, 'conclusion': None}
    }

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
        frame_count += 1
        gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        lsb_frame = np.bitwise_and(gray_frame, 1)
        _, counts = np.unique(lsb_frame, return_counts=True)
        results['lsb_distribution'].append(counts.tolist())

        if np.any(lsb_frame):
            results['suspicious_frames'].append(frame_count)

        dct_transform = fftpack.dct(fftpack.dct(np.float32(gray_frame), axis=0, norm='ortho'), axis=1, norm='ortho')
        dct_mean = np.mean(dct_transform)
        if dct_mean > 50:
            results['dct_anomalies'].append(frame_count)

        entropy_value = shannon_entropy(gray_frame)
        if entropy_value > 7.5:
            results['entropy_anomalies'].append(frame_count)

    cap.release()
    results['frame_count'] = frame_count

    if results['lsb_distribution']:
        observed = np.sum(results['lsb_distribution'], axis=0)
        expected = np.full_like(observed, np.mean(observed))
        chi_stat, p_value = chisquare(observed, expected)

        results['chi_square']['statistic'] = float(chi_stat)
        results['chi_square']['p_value'] = float(p_value)
        results['chi_square']['conclusion'] = (
            "High likelihood of steganography" if p_value < 0.05 else "No significant anomalies"
        )

    return results


@sstegno_bp.route('/sstegno', methods=['POST'])
def sstegno_route():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if not allowed_extension(file.filename):
        return jsonify({'error': 'Unsupported file type'}), 400

    filename = secure_filename(f"{uuid.uuid4().hex}.mp4")
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        # Save uploaded file
        file.save(filepath)

        # Convert video to base64 (optional)
        with open(filepath, 'rb') as f:
            video_bytes = f.read()
            video_base64 = base64.b64encode(video_bytes).decode('utf-8')

        # Analyze video
        results = analyze_video(filepath)

        # Remove temporary file
        os.remove(filepath)

        return jsonify({
            'status': 'success',
            'results': results,
            'video_base64': video_base64  # Return base64 string if needed
        }), 200

    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': f'Processing error: {str(e)}'}), 500
