## eviction manager

### 目标

本文档的主要目标是通过源码分析结合总结概述的方式试图让学习 kubernetes 的相关人员能对对 kubernetes 的 eviction manager 清晰、完整、深入的掌握.

### 总览

当 node 节点的可用计算资源过低时,需要一种机制来保证节点的稳定性,因此 eviction manager 应运而生. 通过 eviction manager 来实现 pod 驱逐,回收计算资源,以达到保证 node 节点的稳定性.

#### eviction 触发的信号来源

既然是驱逐管理器,那我们首先应该想到的是,触发驱逐 pod 的条件是什么? 都有那些驱逐的策略? 当前版本(v1.14.1)中,驱逐的策略有如下几种:

| 名称                        | 描述                                                            |
| --------------------------- | --------------------------------------------------------------- |
| memory.available            | 可用内存                                                        |
| nodefs.available            | 可用文件系统大小                                                |
| nodefs.inodesFree           | 可用 inode                                                      |
| imagefs.available           | 容器运行时用于存储映像和容器可写层的文件系统上可用的存储量      |
| imagefs.inodesFree          | 容器运行时用于存储映像和容器可写层的文件系统上可用的 inode 数量 |
| allocatableMemory.available | 可用于调度 pod 的可用内存                                       |
| pid.available               | pod 可分配的 pid 数量                                           |

通过上面的表格可用看出目前的驱逐策略只支持 memory、fs、pid 相关的.并未支持 cpu.

#### eviction 触发的阈值设置

驱逐策略有了, 那接下来就是触发驱逐策略的条件(阈值)了, 所有的驱逐策略的触发条件的设置都是形如:

```
<策略名称><操作><资源值 | 资源百分比>

```

- 策略名称 上表中的名称.
- 操作 所有的操作都是 **<** 符号.
- 资源值 k8s 资源值的字符串表示形式,如: 1Gi 1G 1024M 1024Mi 等, 或者是百分比的形式,如: 10% 12%等, 如果是百分比的形式则百分比的基数是 node 的某种资源的总值.

此外为了避免回收资源的效率,eviction manager 可以通过设置每次回收资源的最小值来实现

软驱逐的 flag 设置,例如:

```
--eviction-minimum-reclaim="memory.available=0Mi,nodefs.available=500Mi,imagefs.available=2Gi"
```

## 驱逐的分类

当前版本的 eviction manager 支持两种驱逐方式: 1. 软驱逐 2 硬驱逐, 接下来让我们分别来看看这两者,以及他们的区别

### 软驱逐

软驱逐需要管理员设置相应的驱逐的优雅驱逐宽限期,当设置的驱逐阈值达到时, kubelet 不会马上进行 pod 的驱逐操作, 只有超过驱逐宽限期后才会进行驱逐操作,除此之外, 如果已满足软驱逐阈值，则操作员可以指定节点驱逐 pod 时使用的最大允许 pod 终止宽限期。如果指定，则 evition manager 将使用两者中较小的值。如果未指定，则 kubelet 会在没有正常终止的情况下立即进行 pod 的驱逐操作.

软驱逐的 flag 设置:

```
--eviction-soft="": A set of eviction thresholds (e.g. memory.available<1.5Gi) that if met over a corresponding grace period would trigger a pod eviction.
--eviction-soft-grace-period="": A set of eviction grace periods (e.g. memory.available=1m30s) that correspond to how long a soft eviction threshold must hold before triggering a pod eviction.
--eviction-max-pod-grace-period="0": Maximum allowed grace period (in seconds) to use when terminating pods in response to a soft eviction threshold being met.
```

### 硬驱逐

硬驱逐当设置的驱逐阈值达到时,立即进行 pod 的驱逐操作, pod 没有优雅退出的时间.

硬驱逐的 flag 设置:

```
--eviction-hard="": A set of eviction thresholds (e.g. memory.available<1Gi) that if met would trigger a pod eviction.
```

## 驱逐对 pod 的影响

BestEffort pod 消耗最大的阈值资源 将先驱逐

Burstable 如果 pod 的资源使用超过了其请求值,则使用最多的将先驱逐,如果资源没有超过其请求值,则当前使用资源最多的将被驱逐

Guaranteed 如果 pod 的资源使用超过了其请求值,则使用最多的将先驱逐,如果资源没有超过其请求值,则当前使用资源最多的将被驱逐

## 驱逐对 node 的状态的影响

当驱逐策略设置的阈值达到时, 会相应的影响到 node 的状态,主要是 MemoryPressure 和 DiskPressure.

| 节点状态       | 驱逐策略名称                                                               | 状态描述 |
| -------------- | -------------------------------------------------------------------------- | -------- |
| MemoryPressure | memory.available                                                           | 内存压力 |
| DiskPressure   | nodefs.available, nodefs.inodesFree, imagefs.available, imagefs.inodesFree | 磁盘压力 |

## 驱逐对调度的影响

当 node 满足 MemoryPressure 状态时, 调度器会阻止 BestEffort 类型的 pod 调度到该 node 上,当 node 满足 DiskPressure 状态时将阻止所有新建的 pod 调度到该 node 上.
