.class Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0xa
    name = "e"
.end annotation


# instance fields
.field a:I

.field b:Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;


# direct methods
.method constructor <init>(I)V
    .locals 0
    .param p1, "x"    # I

    .prologue
    .line 236
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 237
    iput p1, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;->a:I

    .line 238
    return-void
.end method


# virtual methods
.method public toString()Ljava/lang/String;
    .locals 2

    .prologue
    .line 241
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget v1, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;->a:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v0

    const-string v1, " "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    iget-object v0, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;->b:Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    if-eqz v0, :cond_0

    :goto_0
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :cond_0
    const-string v0, ""

    goto :goto_0
.end method
