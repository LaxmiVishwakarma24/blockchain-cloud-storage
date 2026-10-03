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