.class public Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;
.super Landroid/app/Application;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$f;,
        Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$d;,
        Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;,
        Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    }
.end annotation


# instance fields
.field public a:Ljava/lang/String;

.field public b:Ljava/lang/String;

.field public c:Ljava/util/zip/ZipFile;

.field public d:Z

.field public e:Ljava/lang/reflect/Field;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/reflect/Field;

.field public h:[Ljava/lang/Object;

.field public i:Ljava/lang/reflect/Method;

.field public j:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList",
            "<",
            "Ljava/io/IOException;",
            ">;"
        }
    .end annotation
.end field

.field private k:Z

.field private l:Landroid/os/Handler;

.field public m:Z

.field public n:Landroid/app/Application;


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .prologue
    .line 123
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .prologue
    .line 83
    invoke-direct {p0}, Landroid/app/Application;-><init>()V

    .line 104
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->j:Ljava/util/ArrayList;

    .line 115
    nop

    .line 116
    nop

    .line 117
    nop

    .line 127
    nop

    .line 128
    const/4 v0, 0x0

    iput-boolean v0, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->k:Z

    .line 130
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 295
    new-instance v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$a;

    invoke-direct {v0, p0}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$a;-><init>(Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;)V

    iput-object v0, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->l:Landroid/os/Handler;

    return-void
.end method

.method public static a([I)I
    .locals 4
    .param p0, "nums"    # [I

    .prologue
    .line 186
    array-length v2, p0

    if-nez v2, :cond_0

    const/4 v1, 0x0

    .line 193
    :goto_0
    return v1

    .line 187
    :cond_0
    const/4 v1, 0x0

    .line 188
    .local v1, "j":I
    const/4 v0, 0x0

    .local v0, "i":I
    :goto_1
    array-length v2, p0

    if-ge v0, v2, :cond_2

    .line 189
    aget v2, p0, v0

    aget v3, p0, v1

    if-eq v2, v3, :cond_1

    .line 190
    add-int/lit8 v1, v1, 0x1

    aget v2, p0, v0

    aput v2, p0, v1

    .line 188
    :cond_1
    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    .line 193
    :cond_2
    add-int/lit8 v1, v1, 0x1

    goto :goto_0
.end method

.method private a()V
    .locals 23

    .prologue
    .line 473
    move-object/from16 v0, p0

    iget-boolean v0, v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->m:Z

    move/from16 v20, v0

    if-eqz v20, :cond_1

    .line 534
    :cond_0
    :goto_0
    return-void

    .line 476
    :cond_1
    move-object/from16 v0, p0

    iget-object v0, v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->a:Ljava/lang/String;

    move-object/from16 v20, v0

    invoke-static/range {v20 .. v20}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v20

    if-nez v20, :cond_0

    .line 480
    invoke-virtual/range {p0 .. p0}, Landroid/app/Application;->getBaseContext()Landroid/content/Context;

    move-result-object v5

    .line 482
    .local v5, "baseContext":Landroid/content/Context;
    move-object/from16 v0, p0

    iget-object v0, v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->a:Ljava/lang/String;

    move-object/from16 v20, v0

    invoke-static/range {v20 .. v20}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v7

    .line 483
    .local v7, "delegateClass":Ljava/lang/Class;, "Ljava/lang/Class<*>;"
    invoke-virtual {v7}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;

    move-result-object v20

    check-cast v20, Landroid/app/Application;

    move-object/from16 v0, v20

    move-object/from16 v1, p0

    iput-object v0, v1, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->n:Landroid/app/Application;

    .line 485
    const/16 v20, 0x1

    move/from16 v0, v20

    new-array v0, v0, [Ljava/lang/Class;

    move-object/from16 v20, v0

    const/16 v21, 0x0

    const-class v22, Landroid/content/Context;

    aput-object v22, v20, v21

    const-class v21, Landroid/app/Application;

    const-string v22, "attach"

    move-object/from16 v0, v21

    move-object/from16 v1, v22

    move-object/from16 v2, v20

    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v4

    .line 486
    .local v4, "attach":Ljava/lang/reflect/Method;
    const/16 v20, 0x1

    move/from16 v0, v20

    invoke-virtual {v4, v0}, Ljava/lang/reflect/Method;->setAccessible(Z)V

    .line 487
    move-object/from16 v0, p0

    iget-object v0, v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->n:Landroid/app/Application;

    move-object/from16 v20, v0

    const/16 v21, 0x1

    move/from16 v0, v21

    new-array v0, v0, [Ljava/lang/Object;

    move-object/from16 v21, v0

    const/16 v22, 0x0

    aput-object v5, v21, v22

    move-object/from16 v0, v20

    move-object/from16 v1, v21

    invoke-virtual {v4, v0, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 491
    const-string v20, "android.app.ContextImpl"

    invoke-static/range {v20 .. v20}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v6

    .line 493
    .local v6, "contextImplClass":Ljava/lang/Class;, "Ljava/lang/Class<*>;"
    const-string v20, "mOuterContext"

    move-object/from16 v0, v20

    invoke-virtual {v6, v0}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v17

    .line 494
    .local v17, "mOuterContextField":Ljava/lang/reflect/Field;
    const/16 v20, 0x1

    move-object/from16 v0, v17

    move/from16 v1, v20

    invoke-virtual {v0, v1}, Ljava/lang/reflect/Field;->setAccessible(Z)V

    .line 495
    move-object/from16 v0, p0

    iget-object v0, v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->n:Landroid/app/Application;

    move-object/from16 v20, v0

    move-object/from16 v0, v17

    move-object/from16 v1, v20

    invoke-virtual {v0, v5, v1}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 498
    const-string v20, "mMainThread"

    move-object/from16 v0, v20

    invoke-virtual {v6, v0}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v16

    .line 499
    .local v16, "mMainThreadField":Ljava/lang/reflect/Field;
    const/16 v20, 0x1

    move-object/from16 v0, v16

    move/from16 v1, v20

    invoke-virtual {v0, v1}, Ljava/lang/reflect/Field;->setAccessible(Z)V

    .line 500
    move-object/from16 v0, v16

    invoke-virtual {v0, v5}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v15

    .line 503
    .local v15, "mMainThread":Ljava/lang/Object;
    const-string v20, "android.app.ActivityThread"

    invoke-static/range {v20 .. v20}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v3

    .line 504
    .local v3, "activityThreadClass":Ljava/lang/Class;, "Ljava/lang/Class<*>;"
    const-string v20, "mInitialApplication"

    move-object/from16 v0, v20

    invoke-virtual {v3, v0}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v14

    .line 505
    .local v14, "mInitialApplicationField":Ljava/lang/reflect/Field;
    const/16 v20, 0x1

    move/from16 v0, v20

    invoke-virtual {v14, v0}, Ljava/lang/reflect/Field;->setAccessible(Z)V

    .line 506
    move-object/from16 v0, p0

    iget-object v0, v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->n:Landroid/app/Application;

    move-object/from16 v20, v0

    move-object/from16 v0, v20

    invoke-virtual {v14, v15, v0}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 508
    const-string v20, "mAllApplications"

    move-object/from16 v0, v20

    invoke-virtual {v3, v0}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v10

    .line 509
    .local v10, "mAllApplicationsField":Ljava/lang/reflect/Field;
    const/16 v20, 0x1

    move/from16 v0, v20

    invoke-virtual {v10, v0}, Ljava/lang/reflect/Field;->setAccessible(Z)V

    .line 510
    invoke-virtual {v10, v15}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/util/ArrayList;

    .line 511
    .local v9, "mAllApplications":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Landroid/app/Application;>;"
    move-object/from16 v0, p0

    invoke-virtual {v9, v0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 512
    move-object/from16 v0, p0

    iget-object v0, v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->n:Landroid/app/Application;

    move-object/from16 v20, v0

    move-object/from16 v0, v20

    invoke-virtual {v9, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 515
    const-string v20, "mPackageInfo"

    move-object/from16 v0, v20

    invoke-virtual {v6, v0}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v19

    .line 516
    .local v19, "mPackageInfoField":Ljava/lang/reflect/Field;
    const/16 v20, 0x1

    invoke-virtual/range {v19 .. v20}, Ljava/lang/reflect/Field;->setAccessible(Z)V

    .line 517
    move-object/from16 v0, v19

    invoke-virtual {v0, v5}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v18

    .line 519
    .local v18, "mPackageInfo":Ljava/lang/Object;
    const-string v20, "android.app.LoadedApk"

    invoke-static/range {v20 .. v20}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v8

    .line 520
    .local v8, "loadedApkClass":Ljava/lang/Class;, "Ljava/lang/Class<*>;"
    const-string v20, "mApplication"

    move-object/from16 v0, v20

    invoke-virtual {v8, v0}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v11

    .line 521
    .local v11, "mApplicationField":Ljava/lang/reflect/Field;
    const/16 v20, 0x1

    move/from16 v0, v20

    invoke-virtual {v11, v0}, Ljava/lang/reflect/Field;->setAccessible(Z)V

    .line 522
    move-object/from16 v0, p0

    iget-object v0, v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->n:Landroid/app/Application;

    move-object/from16 v20, v0

    move-object/from16 v0, v18

    move-object/from16 v1, v20

    invoke-virtual {v11, v0, v1}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 525
    const-string v20, "mApplicationInfo"

    move-object/from16 v0, v20

    invoke-virtual {v8, v0}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v13

    .line 526
    .local v13, "mApplicationInfoField":Ljava/lang/reflect/Field;
    const/16 v20, 0x1

    move/from16 v0, v20

    invoke-virtual {v13, v0}, Ljava/lang/reflect/Field;->setAccessible(Z)V

    .line 527
    move-object/from16 v0, v18

    invoke-virtual {v13, v0}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Landroid/content/pm/ApplicationInfo;

    .line 528
    .local v12, "mApplicationInfo":Landroid/content/pm/ApplicationInfo;
    move-object/from16 v0, p0

    iget-object v0, v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->a:Ljava/lang/String;

    move-object/from16 v20, v0

    move-object/from16 v0, v20

    iput-object v0, v12, Landroid/content/pm/ApplicationInfo;->className:Ljava/lang/String;

    .line 532
    move-object/from16 v0, p0

    iget-object v0, v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->l:Landroid/os/Handler;

    move-object/from16 v20, v0

    const/16 v21, 0x1

    invoke-virtual/range {v20 .. v21}, Landroid/os/Handler;->sendEmptyMessage(I)Z

    .line 533
    const/16 v20, 0x1

    move/from16 v0, v20

    move-object/from16 v1, p0

    iput-boolean v0, v1, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->m:Z

    goto/16 :goto_0
.end method

.method public static a(Ljava/io/File;)V
    .locals 4
    .param p0, "file"    # Ljava/io/File;

    .prologue
    .line 671
    invoke-virtual {p0}, Ljava/io/File;->isDirectory()Z

    move-result v2

    if-eqz v2, :cond_0

    .line 672
    invoke-virtual {p0}, Ljava/io/File;->listFiles()[Ljava/io/File;

    move-result-object v1

    .line 673
    .local v1, "files":[Ljava/io/File;
    array-length v3, v1

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v3, :cond_1

    aget-object v0, v1, v2

    .line 674
    .local v0, "f":Ljava/io/File;
    invoke-static {v0}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->a(Ljava/io/File;)V

    .line 673
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 677
    .end local v0    # "f":Ljava/io/File;
    .end local v1    # "files":[Ljava/io/File;
    :cond_0
    invoke-virtual {p0}, Ljava/io/File;->delete()Z

    .line 679
    :cond_1
    return-void
.end method

.method public static a(Ljava/io/File;Ljava/io/File;Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$f;)V
    .locals 13
    .param p0, "xZip"    # Ljava/io/File;
    .param p1, "mDir"    # Ljava/io/File;
    .param p2, "mLister"    # Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$f;

    .prologue
    .line 689
    :try_start_0
    invoke-static {p1}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->a(Ljava/io/File;)V

    .line 690
    new-instance v11, Ljava/util/zip/ZipFile;

    invoke-direct {v11, p0}, Ljava/util/zip/ZipFile;-><init>(Ljava/io/File;)V

    .line 692
    .local v11, "zipFile":Ljava/util/zip/ZipFile;
    invoke-virtual {v11}, Ljava/util/zip/ZipFile;->entries()Ljava/util/Enumeration;

    move-result-object v2

    .line 695
    .local v2, "entries":Ljava/util/Enumeration;, "Ljava/util/Enumeration<+Ljava/util/zip/ZipEntry;>;"
    :cond_0
    :goto_0
    invoke-interface {v2}, Ljava/util/Enumeration;->hasMoreElements()Z

    move-result v12

    if-eqz v12, :cond_4

    .line 696
    invoke-interface {v2}, Ljava/util/Enumeration;->nextElement()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Ljava/util/zip/ZipEntry;

    .line 698
    .local v10, "zipEntry":Ljava/util/zip/ZipEntry;
    invoke-virtual {v10}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;

    move-result-object v9

    .line 700
    .local v9, "name":Ljava/lang/String;
    const-string v12, "META-INF/CERT.RSA"

    invoke-virtual {v9, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v12

    if-nez v12, :cond_0

    const-string v12, "META-INF/CERT.SF"

    invoke-virtual {v9, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v12

    if-nez v12, :cond_0

    .line 701
    const-string v12, "META-INF/MANIFEST.MF"

    invoke-virtual {v9, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v12

    if-nez v12, :cond_0

    .line 705
    invoke-virtual {v10}, Ljava/util/zip/ZipEntry;->isDirectory()Z

    move-result v12

    if-nez v12, :cond_0

    .line 706
    new-instance v3, Ljava/io/File;

    invoke-direct {v3, p1, v9}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 708
    .local v3, "file":Ljava/io/File;
    invoke-virtual {v3}, Ljava/io/File;->getParentFile()Ljava/io/File;

    move-result-object v12

    invoke-virtual {v12}, Ljava/io/File;->exists()Z

    move-result v12

    if-nez v12, :cond_1

    .line 709
    invoke-virtual {v3}, Ljava/io/File;->getParentFile()Ljava/io/File;

    move-result-object v12

    invoke-virtual {v12}, Ljava/io/File;->mkdirs()Z

    .line 711
    :cond_1
    invoke-virtual {v3}, Ljava/io/File;->getName()Ljava/lang/String;

    move-result-object v4

    .line 712
    .local v4, "fileName":Ljava/lang/String;
    const-string v12, ".dex"

    invoke-virtual {v4, v12}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    move-result v12

    if-eqz v12, :cond_2

    const-string v12, "classes.dex"

    invoke-static {v4, v12}, Landroid/text/TextUtils;->equals(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z

    move-result v12

    if-nez v12, :cond_2

    .line 713
    invoke-static {v11, v10, v3, p2}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->a(Ljava/util/zip/ZipFile;Ljava/util/zip/ZipEntry;Ljava/io/File;Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$f;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    .line 733
    .end local v2    # "entries":Ljava/util/Enumeration;, "Ljava/util/Enumeration<+Ljava/util/zip/ZipEntry;>;"
    .end local v3    # "file":Ljava/io/File;
    .end local v4    # "fileName":Ljava/lang/String;
    .end local v9    # "name":Ljava/lang/String;
    .end local v10    # "zipEntry":Ljava/util/zip/ZipEntry;
    .end local v11    # "zipFile":Ljava/util/zip/ZipFile;
    :catch_0
    move-exception v1

    .line 734
    .local v1, "e":Ljava/lang/Exception;
    invoke-virtual {v1}, Ljava/lang/Exception;->printStackTrace()V

    .line 736
    .end local v1    # "e":Ljava/lang/Exception;
    :goto_1
    return-void

    .line 716
    .restart local v2    # "entries":Ljava/util/Enumeration;, "Ljava/util/Enumeration<+Ljava/util/zip/ZipEntry;>;"
    .restart local v3    # "file":Ljava/io/File;
    .restart local v4    # "fileName":Ljava/lang/String;
    .restart local v9    # "name":Ljava/lang/String;
    .restart local v10    # "zipEntry":Ljava/util/zip/ZipEntry;
    .restart local v11    # "zipFile":Ljava/util/zip/ZipFile;
    :cond_2
    :try_start_1
    new-instance v5, Ljava/io/FileOutputStream;

    invoke-direct {v5, v3}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    .line 718
    .local v5, "fos":Ljava/io/FileOutputStream;
    new-instance v8, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$d;

    invoke-direct {v8}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$d;-><init>()V

    .line 719
    .local v8, "myTools":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$d;
    invoke-virtual {v8, v10, v11}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$d;->a(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/io/InputStream;

    .line 721
    .local v6, "is":Ljava/io/InputStream;
    const/16 v12, 0x800

    new-array v0, v12, [B

    .line 723
    .local v0, "buffer":[B
    :goto_2
    invoke-virtual {v6, v0}, Ljava/io/InputStream;->read([B)I

    move-result v7

    .local v7, "len":I
    const/4 v12, -0x1

    if-eq v7, v12, :cond_3

    .line 724
    const/4 v12, 0x0

    invoke-virtual {v5, v0, v12, v7}, Ljava/io/FileOutputStream;->write([BII)V

    goto :goto_2

    .line 726
    :cond_3
    invoke-virtual {v6}, Ljava/io/InputStream;->close()V

    .line 727
    invoke-virtual {v5}, Ljava/io/FileOutputStream;->close()V

    goto/16 :goto_0

    .line 732
    .end local v0    # "buffer":[B
    .end local v3    # "file":Ljava/io/File;
    .end local v4    # "fileName":Ljava/lang/String;
    .end local v5    # "fos":Ljava/io/FileOutputStream;
    .end local v6    # "is":Ljava/io/InputStream;
    .end local v7    # "len":I
    .end local v8    # "myTools":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$d;
    .end local v9    # "name":Ljava/lang/String;
    .end local v10    # "zipEntry":Ljava/util/zip/ZipEntry;
    :cond_4
    invoke-interface {p2, v11}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$f;->a(Ljava/util/zip/ZipFile;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    goto :goto_1
.end method

.method public static a(Ljava/util/zip/ZipFile;Ljava/util/zip/ZipEntry;Ljava/io/File;Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$f;)V
    .locals 5
    .param p0, "zipFile"    # Ljava/util/zip/ZipFile;
    .param p1, "zipEntry"    # Ljava/util/zip/ZipEntry;
    .param p2, "file"    # Ljava/io/File;
    .param p3, "fileLister"    # Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$f;

    .prologue
    .line 758
    :try_start_0
    new-instance v1, Ljava/io/FileOutputStream;

    invoke-direct {v1, p2}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    .line 759
    .local v1, "fos":Ljava/io/FileOutputStream;
    invoke-virtual {p0, p1}, Ljava/util/zip/ZipFile;->getInputStream(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;

    move-result-object v2

    .line 760
    .local v2, "is":Ljava/io/InputStream;
    const/16 v4, 0x800

    new-array v0, v4, [B

    .line 762
    .local v0, "buffer":[B
    :goto_0
    invoke-virtual {v2, v0}, Ljava/io/InputStream;->read([B)I

    move-result v3

    .local v3, "len":I
    const/4 v4, -0x1

    if-eq v3, v4, :cond_0

    .line 763
    const/4 v4, 0x0

    invoke-virtual {v1, v0, v4, v3}, Ljava/io/FileOutputStream;->write([BII)V

    goto :goto_0

    .end local v0    # "buffer":[B
    .end local v1    # "fos":Ljava/io/FileOutputStream;
    .end local v2    # "is":Ljava/io/InputStream;
    .end local v3    # "len":I
    :catch_0
    move-exception v4

    .line 773
    :goto_1
    return-void

    .line 765
    .restart local v0    # "buffer":[B
    .restart local v1    # "fos":Ljava/io/FileOutputStream;
    .restart local v2    # "is":Ljava/io/InputStream;
    .restart local v3    # "len":I
    :cond_0
    invoke-virtual {v2}, Ljava/io/InputStream;->close()V

    .line 766
    invoke-virtual {v1}, Ljava/io/FileOutputStream;->close()V

    .line 770
    invoke-interface {p3, p2}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$f;->a(Ljava/io/File;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1
.end method

.method private c()V
    .locals 6

    .prologue
    .line 653
    :try_start_0
    invoke-virtual {p0}, Landroid/app/Application;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v3

    .line 654
    invoke-virtual {p0}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->getPackageName()Ljava/lang/String;

    move-result-object v4

    .line 653
    const/16 v5, 0x80

    invoke-virtual {v3, v4, v5}, Landroid/content/pm/PackageManager;->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;

    move-result-object v0

    .line 655
    .local v0, "applicationInfo":Landroid/content/pm/ApplicationInfo;
    iget-object v2, v0, Landroid/content/pm/ApplicationInfo;->metaData:Landroid/os/Bundle;

    .line 656
    .local v2, "metaData":Landroid/os/Bundle;
    if-eqz v2, :cond_1

    .line 657
    const-string v3, "app_name"

    invoke-virtual {v2, v3}, Landroid/os/Bundle;->containsKey(Ljava/lang/String;)Z

    move-result v3

    if-eqz v3, :cond_0

    .line 658
    const-string v3, "app_name"

    invoke-virtual {v2, v3}, Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    iput-object v3, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->a:Ljava/lang/String;

    .line 660
    :cond_0
    const-string v3, "app_version"

    invoke-virtual {v2, v3}, Landroid/os/Bundle;->containsKey(Ljava/lang/String;)Z

    move-result v3

    if-eqz v3, :cond_1

    .line 661
    const-string v3, "app_version"

    invoke-virtual {v2, v3}, Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    iput-object v3, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->b:Ljava/lang/String;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 668
    .end local v0    # "applicationInfo":Landroid/content/pm/ApplicationInfo;
    .end local v2    # "metaData":Landroid/os/Bundle;
    :cond_1
    :goto_0
    return-void

    .line 665
    :catch_0
    move-exception v1

    .line 666
    .local v1, "e":Ljava/lang/Exception;
    invoke-virtual {v1}, Ljava/lang/Exception;->printStackTrace()V

    goto :goto_0
.end method

.method private d()V
    .locals 7

    .prologue
    const/4 v6, 0x1

    .line 134
    iget-boolean v5, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->k:Z

    if-eqz v5, :cond_0

    .line 135
    iput-boolean v6, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->k:Z

    .line 136
    const/4 v5, 0x7

    invoke-virtual {p0, v6, v5}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->a(II)Ljava/lang/String;

    .line 141
    new-instance v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    invoke-direct {v0, v6}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;-><init>(I)V

    .line 142
    .local v0, "l1":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    new-instance v1, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    const/4 v5, 0x2

    invoke-direct {v1, v5}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;-><init>(I)V

    .line 143
    .local v1, "l2":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    new-instance v2, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    const/4 v5, 0x3

    invoke-direct {v2, v5}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;-><init>(I)V

    .line 144
    .local v2, "l3":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    new-instance v3, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    const/4 v5, 0x4

    invoke-direct {v3, v5}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;-><init>(I)V

    .line 145
    .local v3, "l4":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    new-instance v4, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    const/4 v5, 0x5

    invoke-direct {v4, v5}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;-><init>(I)V

    .line 146
    .local v4, "l5":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    iput-object v1, v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;->b:Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    .line 147
    iput-object v2, v1, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;->b:Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    .line 148
    iput-object v3, v2, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;->b:Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    .line 149
    iput-object v4, v3, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;->b:Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    .line 152
    .end local v0    # "l1":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .end local v1    # "l2":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .end local v2    # "l3":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .end local v3    # "l4":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .end local v4    # "l5":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    :cond_0
    return-void
.end method

.method private e()Ljava/util/ArrayList;
    .locals 13
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/ArrayList",
            "<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .prologue
    .line 159
    iget-boolean v10, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->k:Z

    if-eqz v10, :cond_1

    .line 160
    const-string v7, ""

    .line 161
    .local v7, "f":Ljava/lang/String;
    new-instance v8, Ljava/util/ArrayList;

    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 162
    .local v8, "list":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Ljava/lang/String;>;"
    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 163
    .local v6, "dir":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Ljava/lang/String;>;"
    new-instance v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    const/4 v10, 0x2

    invoke-direct {v0, v10}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;-><init>(I)V

    .line 164
    .local v0, "a1":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    new-instance v1, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    const/4 v10, 0x4

    invoke-direct {v1, v10}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;-><init>(I)V

    .line 165
    .local v1, "a2":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    new-instance v2, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    const/4 v10, 0x3

    invoke-direct {v2, v10}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;-><init>(I)V

    .line 166
    .local v2, "a3":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    iput-object v1, v0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;->b:Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    .line 167
    iput-object v2, v1, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;->b:Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    .line 169
    new-instance v3, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    const/4 v10, 0x5

    invoke-direct {v3, v10}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;-><init>(I)V

    .line 170
    .local v3, "b1":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    new-instance v4, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    const/4 v10, 0x6

    invoke-direct {v4, v10}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;-><init>(I)V

    .line 171
    .local v4, "b2":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    new-instance v5, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    const/4 v10, 0x4

    invoke-direct {v5, v10}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;-><init>(I)V

    .line 172
    .local v5, "b3":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    iput-object v4, v3, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;->b:Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    .line 173
    iput-object v5, v4, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;->b:Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;

    .line 174
    const/4 v10, 0x4

    new-array v9, v10, [I

    const/4 v10, 0x0

    const/4 v11, 0x3

    aput v11, v9, v10

    const/4 v10, 0x1

    const/4 v11, 0x2

    aput v11, v9, v10

    const/4 v10, 0x2

    const/4 v11, 0x2

    aput v11, v9, v10

    const/4 v10, 0x3

    const/4 v11, 0x3

    aput v11, v9, v10

    .line 175
    .local v9, "nums":[I
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    move-result v10

    if-nez v10, :cond_0

    .line 182
    .end local v0    # "a1":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .end local v1    # "a2":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .end local v2    # "a3":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .end local v3    # "b1":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .end local v4    # "b2":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .end local v5    # "b3":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .end local v6    # "dir":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Ljava/lang/String;>;"
    .end local v7    # "f":Ljava/lang/String;
    .end local v8    # "list":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Ljava/lang/String;>;"
    .end local v9    # "nums":[I
    :goto_0
    return-object v6

    .line 177
    .restart local v0    # "a1":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .restart local v1    # "a2":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .restart local v2    # "a3":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .restart local v3    # "b1":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .restart local v4    # "b2":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .restart local v5    # "b3":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .restart local v6    # "dir":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Ljava/lang/String;>;"
    .restart local v7    # "f":Ljava/lang/String;
    .restart local v8    # "list":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Ljava/lang/String;>;"
    .restart local v9    # "nums":[I
    :cond_0
    const/4 v10, 0x3

    new-array v10, v10, [I

    const/4 v11, 0x0

    const/4 v12, 0x1

    aput v12, v10, v11

    const/4 v11, 0x1

    const/4 v12, 0x1

    aput v12, v10, v11

    const/4 v11, 0x2

    const/4 v12, 0x2

    aput v12, v10, v11

    invoke-static {v10}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->a([I)I

    move-object v6, v8

    .line 179
    goto :goto_0

    .line 182
    .end local v0    # "a1":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .end local v1    # "a2":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .end local v2    # "a3":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .end local v3    # "b1":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .end local v4    # "b2":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .end local v5    # "b3":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$e;
    .end local v6    # "dir":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Ljava/lang/String;>;"
    .end local v7    # "f":Ljava/lang/String;
    .end local v8    # "list":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Ljava/lang/String;>;"
    .end local v9    # "nums":[I
    :cond_1
    const/4 v6, 0x0

    goto :goto_0
.end method


# virtual methods
.method public a(II)Ljava/lang/String;
    .locals 7
    .param p1, "n"    # I
    .param p2, "k"    # I

    .prologue
    .line 199
    new-instance v3, Ljava/util/LinkedList;

    invoke-direct {v3}, Ljava/util/LinkedList;-><init>()V

    .line 200
    .local v3, "num":Ljava/util/List;, "Ljava/util/List<Ljava/lang/Integer;>;"
    const/4 v1, 0x1

    .local v1, "i":I
    :goto_0
    if-gt v1, p1, :cond_0

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-interface {v3, v5}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    .line 201
    :cond_0
    new-array v0, p1, [I

    .line 202
    .local v0, "fact":[I
    const/4 v5, 0x0

    const/4 v6, 0x1

    aput v6, v0, v5

    .line 203
    const/4 v1, 0x1

    :goto_1
    if-ge v1, p1, :cond_1

    add-int/lit8 v5, v1, -0x1

    aget v5, v0, v5

    mul-int/2addr v5, v1

    aput v5, v0, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_1

    .line 204
    :cond_1
    add-int/lit8 p2, p2, -0x1

    .line 205
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 206
    .local v4, "sb":Ljava/lang/StringBuilder;
    add-int/lit8 v1, p1, -0x1

    :goto_2
    if-ltz v1, :cond_2

    .line 207
    aget v5, v0, v1

    div-int v2, p2, v5

    .line 208
    .local v2, "ind":I
    aget v5, v0, v1

    rem-int/2addr p2, v5

    .line 209
    invoke-interface {v3, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 210
    invoke-interface {v3, v2}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    .line 206
    add-int/lit8 v1, v1, -0x1

    goto :goto_2

    .line 212
    .end local v2    # "ind":I
    :cond_2
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    return-object v5
.end method

.method public a(Ljava/util/List;Ljava/io/File;)V
    .locals 8
    .param p2, "versionDir"    # Ljava/io/File;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List",
            "<",
            "Ljava/io/File;",
            ">;",
            "Ljava/io/File;",
            ")V"
        }
    .end annotation

    .prologue
    .local p1, "dexFiles":Ljava/util/List;, "Ljava/util/List<Ljava/io/File;>;"
    const/4 v7, 0x0

    .line 417
    iget-object v2, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->i:Ljava/lang/reflect/Method;

    iget-object v3, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->f:Ljava/lang/Object;

    const/4 v4, 0x3

    new-array v4, v4, [Ljava/lang/Object;

    aput-object p1, v4, v7

    const/4 v5, 0x1

    aput-object p2, v4, v5

    iget-object v5, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->j:Ljava/util/ArrayList;

    const/4 v6, 0x2

    aput-object v5, v4, v6

    invoke-virtual {v2, v3, v4}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Ljava/lang/Object;

    .line 419
    .local v0, "addElements":[Ljava/lang/Object;
    iget-object v2, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->h:[Ljava/lang/Object;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    move-result-object v2

    iget-object v3, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->h:[Ljava/lang/Object;

    array-length v3, v3

    array-length v4, v0

    add-int/2addr v3, v4

    invoke-static {v2, v3}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [Ljava/lang/Object;

    .line 420
    .local v1, "newElements":[Ljava/lang/Object;
    iget-object v2, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->h:[Ljava/lang/Object;

    array-length v3, v2

    invoke-static {v2, v7, v1, v7, v3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 421
    iget-object v2, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->h:[Ljava/lang/Object;

    array-length v2, v2

    array-length v3, v0

    invoke-static {v0, v7, v1, v2, v3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 424
    iget-object v2, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->g:Ljava/lang/reflect/Field;

    iget-object v3, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->f:Ljava/lang/Object;

    invoke-virtual {v2, v3, v1}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 425
    return-void
.end method

.method protected attachBaseContext(Landroid/content/Context;)V
    .locals 10
    .param p1, "base"    # Landroid/content/Context;

    .prologue
    const/4 v7, 0x0

    .line 313
    invoke-super {p0, p1}, Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V

    .line 315
    invoke-direct {p0}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->c()V

    .line 318
    new-instance v0, Ljava/io/File;

    invoke-virtual {p0}, Landroid/app/Application;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    move-result-object v8

    iget-object v8, v8, Landroid/content/pm/ApplicationInfo;->sourceDir:Ljava/lang/String;

    invoke-direct {v0, v8}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 321
    .local v0, "apkFile":Ljava/io/File;
    new-instance v8, Ljava/lang/StringBuilder;

    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v9, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->a:Ljava/lang/String;

    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v8

    const-string v9, "_"

    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v8

    iget-object v9, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->b:Ljava/lang/String;

    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v8

    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v8

    invoke-virtual {p0, v8, v7}, Landroid/app/Application;->getDir(Ljava/lang/String;I)Ljava/io/File;

    move-result-object v6

    .line 322
    .local v6, "versionDir":Ljava/io/File;
    new-instance v1, Ljava/io/File;

    const-string v8, "app"

    invoke-direct {v1, v6, v8}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 323
    .local v1, "appDir":Ljava/io/File;
    new-instance v2, Ljava/io/File;

    const-string v8, "dexDir"

    invoke-direct {v2, v1, v8}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 328
    .local v2, "dexDir":Ljava/io/File;
    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 330
    .local v3, "dexFiles":Ljava/util/List;, "Ljava/util/List<Ljava/io/File;>;"
    nop

    .line 332
    invoke-virtual {v2}, Ljava/io/File;->exists()Z

    move-result v8

    if-eqz v8, :cond_0

    invoke-virtual {v2}, Ljava/io/File;->list()[Ljava/lang/String;

    move-result-object v8

    array-length v8, v8

    if-nez v8, :cond_3

    .line 333
    :cond_0
    nop

    .line 334
    nop

    .line 336
    new-instance v7, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$b;

    invoke-direct {v7, p0, v3}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$b;-><init>(Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;Ljava/util/List;)V

    invoke-static {v0, v1, v7}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->a(Ljava/io/File;Ljava/io/File;Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$f;)V

    .line 370
    :cond_1
    invoke-virtual {p0}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->b()V

    .line 375
    :try_start_0
    iget-object v7, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->c:Ljava/util/zip/ZipFile;

    if-eqz v7, :cond_2

    .line 376
    invoke-virtual {v7}, Ljava/util/zip/ZipFile;->close()V

    .line 379
    :cond_2
    invoke-virtual {p0, v3, v6}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->a(Ljava/util/List;Ljava/io/File;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 383
    :goto_0
    return-void

    .line 362
    :cond_3
    invoke-virtual {v2}, Ljava/io/File;->listFiles()[Ljava/io/File;

    move-result-object v8

    array-length v9, v8

    :goto_1
    if-ge v7, v9, :cond_1

    aget-object v5, v8, v7

    .line 363
    .local v5, "file":Ljava/io/File;
    invoke-interface {v3, v5}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 362
    add-int/lit8 v7, v7, 0x1

    goto :goto_1

    .line 380
    .end local v5    # "file":Ljava/io/File;
    :catch_0
    move-exception v4

    .line 381
    .local v4, "e":Ljava/lang/Exception;
    invoke-virtual {v4}, Ljava/lang/Exception;->printStackTrace()V

    goto :goto_0
.end method

.method public b()V
    .locals 9

    .prologue
    .line 397
    :try_start_0
    new-instance v1, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;

    invoke-direct {v1}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;-><init>()V

    .line 398
    .local v1, "myTools1":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;
    new-instance v2, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;

    invoke-direct {v2}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;-><init>()V

    .line 400
    .local v2, "myTools2":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;
    new-instance v3, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;

    invoke-direct {v3}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;-><init>()V

    .line 402
    .local v3, "myTools3":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;
    invoke-virtual {p0}, Landroid/app/Application;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v4

    const-string v5, "pathList"

    invoke-virtual {v1, v4, v5}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v4

    iput-object v4, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->e:Ljava/lang/reflect/Field;

    .line 403
    invoke-virtual {p0}, Landroid/app/Application;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    iput-object v4, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->f:Ljava/lang/Object;

    .line 405
    const-string v5, "dexElements"

    invoke-virtual {v2, v4, v5}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v4

    iput-object v4, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->g:Ljava/lang/reflect/Field;

    .line 406
    iget-object v5, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->f:Ljava/lang/Object;

    invoke-virtual {v4, v5}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, [Ljava/lang/Object;

    iput-object v4, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->h:[Ljava/lang/Object;

    .line 408
    iget-object v4, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->f:Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    const-string v5, "makePathElements"

    const/4 v6, 0x3

    :try_start_1
    new-array v6, v6, [Ljava/lang/Class;

    const/4 v7, 0x0

    const-class v8, Ljava/util/List;

    aput-object v8, v6, v7

    const/4 v7, 0x1

    const-class v8, Ljava/io/File;

    aput-object v8, v6, v7

    const/4 v7, 0x2

    const-class v8, Ljava/util/List;

    aput-object v8, v6, v7

    invoke-static {v4, v5, v6}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;->a(Ljava/lang/Object;Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v4

    iput-object v4, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->i:Ljava/lang/reflect/Method;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 414
    .end local v1    # "myTools1":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;
    .end local v2    # "myTools2":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;
    .end local v3    # "myTools3":Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod$c;
    :goto_0
    return-void

    .line 409
    :catch_0
    move-exception v0

    .line 410
    .local v0, "e":Ljava/lang/Exception;
    invoke-virtual {v0}, Ljava/lang/Exception;->printStackTrace()V

    goto :goto_0
.end method

.method public createPackageContext(Ljava/lang/String;I)Landroid/content/Context;
    .locals 2
    .param p1, "packageName"    # Ljava/lang/String;
    .param p2, "flags"    # I

    .prologue
    .line 458
    iget-object v1, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->a:Ljava/lang/String;

    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v1

    if-eqz v1, :cond_0

    .line 459
    invoke-super {p0, p1, p2}, Landroid/app/Application;->createPackageContext(Ljava/lang/String;I)Landroid/content/Context;

    move-result-object v1

    .line 466
    :goto_0
    return-object v1

    .line 462
    :cond_0
    :try_start_0
    invoke-direct {p0}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->a()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 466
    :goto_1
    iget-object v1, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->n:Landroid/app/Application;

    goto :goto_0

    .line 463
    :catch_0
    move-exception v0

    .line 464
    .local v0, "e":Ljava/lang/Exception;
    invoke-virtual {v0}, Ljava/lang/Exception;->printStackTrace()V

    goto :goto_1
.end method

.method public getPackageName()Ljava/lang/String;
    .locals 1

    .prologue
    .line 450
    iget-object v0, p0, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->a:Ljava/lang/String;

    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-nez v0, :cond_0

    .line 451
    const-string v0, ""

    .line 453
    :goto_0
    return-object v0

    :cond_0
    invoke-super {p0}, Landroid/app/Application;->getPackageName()Ljava/lang/String;

    move-result-object v0

    goto :goto_0
.end method

.method public onCreate()V
    .locals 1

    .prologue
    .line 432
    invoke-super {p0}, Landroid/app/Application;->onCreate()V

    .line 434
    :try_start_0
    invoke-direct {p0}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->a()V

    .line 436
    invoke-direct {p0}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->d()V

    .line 437
    invoke-direct {p0}, Lcom/lzsEsq/dykSgp/jhvqZx/pupsPVlBod;->e()Ljava/util/ArrayList;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 441
    :goto_0
    return-void

    .line 438
    :catch_0
    move-exception v0

    .line 439
    .local v0, "e":Ljava/lang/Exception;
    invoke-virtual {v0}, Ljava/lang/Exception;->printStackTrace()V

    goto :goto_0
.end method
