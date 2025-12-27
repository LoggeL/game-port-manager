FROM fedora:42

# Install python and firewalld (for firewall-cmd)
RUN dnf install -y python3 python3-pip firewalld && \
    dnf clean all

WORKDIR /app

# Install python dependencies
RUN pip3 install fastapi uvicorn python-multipart jinja2 passlib[bcrypt] python-jose[cryptography]

# Copy application code
COPY main.py .
COPY create_user.py .
COPY templates/ templates/

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
