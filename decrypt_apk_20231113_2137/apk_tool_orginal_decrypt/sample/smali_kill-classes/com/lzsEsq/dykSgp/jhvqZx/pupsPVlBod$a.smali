.class Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$a;
.super Landroid/os/Handler;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic a:Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;


# direct methods
.method constructor <init>(Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;)V
    .locals 0
    .param p1, "this$0"    # Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;

    .prologue
    .line 295
    iput-object p1, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$a;->a:Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;

    invoke-direct {p0}, Landroid/os/Handler;-><init>()V

    return-void
.end method


# virtual methods
.method public handleMessage(Landroid/os/Message;)V
    .locals 1
    .param p1, "msg"    # Landroid/os/Message;

    .prologue
    .line 298
    iget-object v0, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$a;->a:Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;

    iget-object v0, v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->n:Landroid/app/Application;

    invoke-virtual {v0}, Landroid/app/Application;->onCreate()V

    .line 299
    return-void
.end method
