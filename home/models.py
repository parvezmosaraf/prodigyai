from django.db import models
class CV (models.Model):
    cv = models.FileField(upload_to="Media")
    def __str__(self) -> str:
        return super().__str__()
