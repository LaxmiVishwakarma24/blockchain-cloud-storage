import click


def register_cli(app):
    @app.cli.command("seed")
    def seed():
        """Create default roles and permissions."""
        from .seed import seed_roles_and_permissions

        seed_roles_and_permissions()
        click.echo("Seeded roles and permissions.")

    @app.cli.command("create-admin")
    @click.argument("email")
    @click.argument("username")
    @click.password_option()
    def create_admin(email, username, password):
        """Create an ADMIN account (prompts for the password)."""
        from .auth import services
        from .extensions import db
        from .models import Role, User

        problems = services.validate_password(password)
        if problems:
            raise click.ClickException(" ".join(problems))
        role = Role.query.filter_by(name="ADMIN").first()
        if role is None:
            raise click.ClickException("Roles are missing. Run 'flask seed' first.")
        if User.query.filter_by(email=email.lower()).first():
            raise click.ClickException("A user with that email already exists.")
        user = User(email=email.lower(), username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Admin created: {user.email}")

    @app.cli.command("init-storage")
    def init_storage():
        """Create (MinIO) or verify (S3) the storage bucket."""
        from .storage import StorageError, get_storage

        try:
            storage = get_storage()
        except StorageError as exc:
            detail = f" ({exc.__cause__})" if exc.__cause__ else ""
            raise click.ClickException(f"{exc}{detail}")
        click.echo(f"Storage ready: provider={storage.provider}, bucket={storage.bucket}")

    @app.cli.command("generate-key")
    def generate_key_command():
        """Print a new random AES-256 key for ENCRYPTION_KEY."""
        from .security.encryption import generate_key

        click.echo(generate_key())

    @app.cli.command("verify-all")
    def verify_all():
        """Verify the current version of every active file and print a summary."""
        from .files import integrity
        from .models import File
        from .security.encryption import EncryptionConfigError
        from .storage import StorageError

        counts = {integrity.VERIFIED: 0, integrity.MISMATCH: 0, integrity.MISSING: 0}
        skipped = 0
        for file in File.query.filter_by(is_deleted=False).order_by(File.id).all():
            version = file.current_version
            if version is None:
                continue
            try:
                status, _, reason = integrity.check_version(version)
            except (EncryptionConfigError, StorageError) as exc:
                skipped += 1
                click.echo(f"file {file.id}: could not be checked ({type(exc).__name__})")
                continue
            integrity.record_verification(None, file, version, status, reason)
            counts[status] += 1
            if status != integrity.VERIFIED:
                click.echo(f"file {file.id} version {version.version_number}: {status} ({reason})")
        click.echo(
            f"{counts[integrity.VERIFIED]} verified, {counts[integrity.MISMATCH]} mismatched, "
            f"{counts[integrity.MISSING]} missing, {skipped} could not be checked."
        )