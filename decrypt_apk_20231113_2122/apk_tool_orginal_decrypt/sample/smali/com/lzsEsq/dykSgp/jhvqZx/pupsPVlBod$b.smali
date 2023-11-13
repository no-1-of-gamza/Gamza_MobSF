.class Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$b;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$f;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->attachBaseContext(Landroid/content/Context;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic a:Ljava/util/List;

.field final synthetic b:Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;


# direct methods
.method constructor <init>(Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;Ljava/util/List;)V
    .locals 0
    .param p1, "this$0"    # Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;

    .prologue
    .line 336
    iput-object p1, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$b;->b:Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;

    iput-object p2, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$b;->a:Ljava/util/List;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Ljava/io/File;)V
    .locals 0
    .param p1, "file"    # Ljava/io/File;

    .prologue
    .line 352
    invoke-virtual {p0, p1}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$b;->b(Ljava/io/File;)V

    .line 353
    return-void
.end method

.method public a(Ljava/util/zip/ZipFile;)V
    .locals 2
    .param p1, "zipFile"    # Ljava/util/zip/ZipFile;

    .prologue
    .line 357
    iget-object v0, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$b;->b:Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;

    const/4 v1, 0x0

    iput-boolean v1, v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->d:Z

    .line 358
    iput-object p1, v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->c:Ljava/util/zip/ZipFile;

    .line 359
    return-void
.end method

.method b(Ljava/io/File;)V
    .locals 3
    .param p1, "file"    # Ljava/io/File;

    .prologue
    .line 339
    :try_start_0
    new-instance v1, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;

    invoke-direct {v1}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;-><init>()V

    .line 341
    .local v1, "tools":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;
    invoke-static {p1}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;->a(Ljava/io/File;)[B

    move-result-object v0

    .line 343
    .local v0, "bytes":[B
    invoke-virtual {p1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v2

    invoke-static {v0, v2}, Lcom/lzsEsq/dykSgp/jhvqZx/ymcBssEDD;->decrypt([BLjava/lang/String;)V

    .line 344
    iget-object v2, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$b;->a:Ljava/util/List;

    invoke-interface {v2, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 346
    nop

    .line 347
    .end local v0    # "bytes":[B
    .end local v1    # "tools":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;
    :goto_0
    return-void

    :catch_0
    move-exception v2

    goto :goto_0
.end method
